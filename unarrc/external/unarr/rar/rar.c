/* Copyright 2015 the unarr project authors (see AUTHORS file).
   License: LGPLv3 */

#include "rar.h"

/***** multi-volume support *****/

struct rar_multi_vol_ctx {
    ar_stream *original_stream; /* volume 0 – owned by the caller, never closed here */
    char **paths;               /* all volume paths (paths[0] == volume 0) */
    int num_paths;
    int current;                /* index of the currently active volume */
    ar_stream *current_opened;  /* stream we opened for volume current (NULL for volume 0) */
};

/* Parse the RAR headers of a continuation volume and position 'stream' at
   the start of the compressed data.  Returns true and fills *data_left on
   success. */
static bool rar_find_continuation_data(ar_stream *stream, size_t *data_left_out)
{
    if (!ar_seek(stream, FILE_SIGNATURE_SIZE, SEEK_SET))
        return false;

    for (;;) {
        off64_t header_start = ar_tell(stream);
        unsigned char header_data[7];
        if (ar_read(stream, header_data, 7) != 7)
            return false;

        uint8_t  type  = header_data[2];
        uint16_t flags = (uint16_t)(header_data[3] | (header_data[4] << 8));
        uint16_t hsize = (uint16_t)(header_data[5] | (header_data[6] << 8));
        uint64_t datasize = 0;

        if ((flags & LHD_LONG_BLOCK) || type == TYPE_FILE_ENTRY) {
            unsigned char size_data[4];
            if (ar_read(stream, size_data, 4) != 4)
                return false;
            datasize = (uint32_t)((uint8_t)size_data[0] |
                                  ((uint8_t)size_data[1] << 8) |
                                  ((uint8_t)size_data[2] << 16) |
                                  ((uint32_t)(uint8_t)size_data[3] << 24));
        }

        if (type == TYPE_FILE_ENTRY) {
            /* read the fixed part of the file entry to check LHD_LARGE */
            unsigned char entry_data[21];
            if (ar_read(stream, entry_data, 21) != 21)
                return false;
            if (flags & LHD_LARGE) {
                unsigned char more_data[8];
                if (ar_read(stream, more_data, 8) != 8)
                    return false;
                datasize += (uint64_t)((uint32_t)((uint8_t)more_data[0] |
                                                   ((uint8_t)more_data[1] << 8) |
                                                   ((uint8_t)more_data[2] << 16) |
                                                   ((uint32_t)(uint8_t)more_data[3] << 24)));
            }
            /* data begins right after the header */
            *data_left_out = (size_t)datasize;
            return ar_seek(stream, header_start + hsize, SEEK_SET);
        }

        /* skip to the next header */
        if (!ar_seek(stream, header_start + hsize + (off64_t)datasize, SEEK_SET))
            return false;
    }
}

static void rar_multi_vol_ctx_free(struct rar_multi_vol_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->current_opened)
        ar_close(ctx->current_opened);
    for (int i = 0; i < ctx->num_paths; i++)
        free(ctx->paths[i]);
    free(ctx->paths);
    free(ctx);
}

static bool rar_next_volume(ar_archive_rar *rar)
{
    struct rar_multi_vol_ctx *ctx = (struct rar_multi_vol_ctx *)rar->volume_ctx;
    if (!ctx || ctx->current + 1 >= ctx->num_paths)
        return false;

    ctx->current++;
    ar_stream *new_stream = ar_open_file(ctx->paths[ctx->current]);
    if (!new_stream) {
        ctx->current--;
        return false;
    }

    size_t new_data_left = 0;
    if (!rar_find_continuation_data(new_stream, &new_data_left)) {
        ar_close(new_stream);
        ctx->current--;
        return false;
    }

    /* close the previously opened continuation stream */
    if (ctx->current_opened)
        ar_close(ctx->current_opened);
    ctx->current_opened = new_stream;

    rar->super.stream        = new_stream;
    rar->progress.data_left  = new_data_left;
    rar->uncomp.br.at_eof    = false;
    return true;
}

/***** rar archive *****/

static void rar_close(ar_archive *ar)
{
    ar_archive_rar *rar = (ar_archive_rar *)ar;
    free(rar->entry.name);
    rar_clear_uncompress(&rar->uncomp);
    if (rar->volume_ctx)
        rar_multi_vol_ctx_free((struct rar_multi_vol_ctx *)rar->volume_ctx);
}

static bool rar_parse_entry(ar_archive *ar, off64_t offset)
{
    ar_archive_rar *rar = (ar_archive_rar *)ar;
    struct rar_header header;
    struct rar_entry entry;

    /* After extracting a split file we may have switched to a continuation
       volume.  Reset to the original stream so that the next ar_parse_entry
       (seeking to entry_offset_next in volume 0) works correctly. */
    if (rar->volume_ctx) {
        struct rar_multi_vol_ctx *ctx = (struct rar_multi_vol_ctx *)rar->volume_ctx;
        if (ctx->current > 0) {
            ar->stream = ctx->original_stream;
            ctx->current = 0;
            if (ctx->current_opened) {
                ar_close(ctx->current_opened);
                ctx->current_opened = NULL;
            }
        }
    }

    bool out_of_order = offset != ar->entry_offset_next;

    if (!ar_seek(ar->stream, offset, SEEK_SET)) {
        warn("Couldn't seek to offset %" PRIi64, offset);
        return false;
    }

    for (;;) {
        ar->entry_offset = ar_tell(ar->stream);
        ar->entry_size_uncompressed = 0;

        if (!rar_parse_header(ar, &header))
            return false;

        ar->entry_offset_next = ar->entry_offset + header.size + header.datasize;
        if (ar->entry_offset_next < ar->entry_offset + header.size) {
            warn("Integer overflow due to overly large data size");
            return false;
        }

        switch (header.type) {
        case TYPE_MAIN_HEADER:
            if ((header.flags & MHD_PASSWORD)) {
                warn("Encrypted archives aren't supported");
                return false;
            }
            ar_skip(ar->stream, 6 /* reserved data */);
            if ((header.flags & MHD_ENCRYPTVER)) {
                log("MHD_ENCRYPTVER is set");
                ar_skip(ar->stream, 1);
            }
            if ((header.flags & MHD_COMMENT))
                log("MHD_COMMENT is set");
            if (ar_tell(ar->stream) - ar->entry_offset > header.size) {
                warn("Invalid RAR header size: %d", header.size);
                return false;
            }
            rar->archive_flags = header.flags;
            break;

        case TYPE_FILE_ENTRY:
            if (!rar_parse_header_entry(rar, &header, &entry))
                return false;
            if ((header.flags & LHD_PASSWORD))
                warn("Encrypted entries will fail to uncompress");
            if ((header.flags & LHD_DIRECTORY) == LHD_DIRECTORY) {
                if (header.datasize == 0) {
                    log("Skipping directory entry \"%s\"", rar_get_name(ar, false));
                    break;
                }
                warn("Can't skip directory entries containing data");
            }
            if ((header.flags & LHD_SPLIT_AFTER))
                log("File continues in next volume");
            ar->entry_size_uncompressed = (size_t)entry.size;
            ar->entry_filetime = ar_conv_dosdate_to_filetime(entry.dosdate);
            if (!rar->entry.solid || rar->entry.method == METHOD_STORE || out_of_order) {
                rar_clear_uncompress(&rar->uncomp);
                memset(&rar->solid, 0, sizeof(rar->solid));
            }
            else {
                br_clear_leftover_bits(&rar->uncomp);
            }

            rar->solid.restart = rar->entry.solid && (out_of_order || !rar->solid.part_done);
            rar->solid.part_done = !ar->entry_size_uncompressed;
            rar->progress.data_left = (size_t)header.datasize;
            rar->progress.bytes_done = 0;
            rar->progress.crc = 0;

            /* TODO: CRC checks don't always hold (claim in XADRARParser.m @readBlockHeader) */
            if (!rar_check_header_crc(ar))
                warn("Invalid header checksum @%" PRIi64, ar->entry_offset);
            if (ar_tell(ar->stream) != ar->entry_offset + rar->entry.header_size) {
                warn("Couldn't seek to offset %" PRIi64, ar->entry_offset + rar->entry.header_size);
                return false;
            }
            return true;

        case TYPE_NEWSUB:
            log("Skipping newsub header @%" PRIi64, ar->entry_offset);
            break;

        case TYPE_END_OF_ARCHIVE:
            ar->at_eof = true;
            return false;

        default:
            log("Unknown RAR header type %02x", header.type);
            break;
        }

        /* TODO: CRC checks don't always hold (claim in XADRARParser.m @readBlockHeader) */
        if (!rar_check_header_crc(ar))
            warn("Invalid header checksum @%" PRIi64, ar->entry_offset);
        if (!ar_seek(ar->stream, ar->entry_offset_next, SEEK_SET)) {
            warn("Couldn't seek to offset %" PRIi64, ar->entry_offset_next);
            return false;
        }
    }
}

/* stored (uncompressed) data – handles volume boundaries transparently */
static bool rar_copy_stored(ar_archive_rar *rar, void *buffer, size_t count)
{
    uint8_t *buf = (uint8_t *)buffer;
    size_t remaining = count;

    while (remaining > 0) {
        if (rar->progress.data_left == 0) {
            if (!rar->next_volume || !rar->next_volume(rar)) {
                warn("Unexpected EOS in stored data");
                return false;
            }
        }
        size_t chunk = remaining < rar->progress.data_left ? remaining : rar->progress.data_left;
        if (ar_read(rar->super.stream, buf, chunk) != chunk) {
            warn("Unexpected EOF in stored data");
            return false;
        }
        buf += chunk;
        rar->progress.data_left -= chunk;
        rar->progress.bytes_done += chunk;
        remaining -= chunk;
    }
    return true;
}

static bool rar_restart_solid(ar_archive *ar)
{
    ar_archive_rar *rar = (ar_archive_rar *)ar;
    off64_t current_offset = ar->entry_offset;
    log("Restarting decompression for solid entry");
    if (!ar_parse_entry_at(ar, ar->entry_offset_first)) {
        ar_parse_entry_at(ar, current_offset);
        return false;
    }
    while (ar->entry_offset < current_offset) {
        size_t size = ar->entry_size_uncompressed;
        rar->solid.restart = false;
        while (size > 0) {
            unsigned char buffer[1024];
            size_t count = smin(size, sizeof(buffer));
            if (!ar_entry_uncompress(ar, buffer, count)) {
                ar_parse_entry_at(ar, current_offset);
                return false;
            }
            size -= count;
        }
        if (!ar_parse_entry(ar)) {
            ar_parse_entry_at(ar, current_offset);
            return false;
        }
    }
    rar->solid.restart = false;
    return true;
}

static bool rar_uncompress(ar_archive *ar, void *buffer, size_t count)
{
    ar_archive_rar *rar = (ar_archive_rar *)ar;
    if (count > ar->entry_size_uncompressed - rar->progress.bytes_done) {
        warn("Requesting too much data (%" PRIuPTR " < %" PRIuPTR ")", ar->entry_size_uncompressed - rar->progress.bytes_done, count);
        return false;
    }
    if (rar->entry.method == METHOD_STORE) {
        if (!rar_copy_stored(rar, buffer, count))
            return false;
    }
    else if (rar->entry.method == METHOD_FASTEST || rar->entry.method == METHOD_FAST ||
             rar->entry.method == METHOD_NORMAL || rar->entry.method == METHOD_GOOD ||
             rar->entry.method == METHOD_BEST) {
        if (rar->solid.restart && !rar_restart_solid(ar)) {
            warn("Failed to produce the required solid decompression state");
            return false;
        }
        if (!rar_uncompress_part(rar, buffer, count))
            return false;
    }
    else {
        warn("Unknown compression method %#02x", rar->entry.method);
        return false;
    }

    rar->progress.crc = ar_crc32(rar->progress.crc, buffer, count);
    if (rar->progress.bytes_done < ar->entry_size_uncompressed)
        return true;
    if (rar->progress.data_left)
        log("Compressed block has more data than required");
    rar->solid.part_done = true;
    rar->solid.size_total += rar->progress.bytes_done;
    if (rar->progress.crc != rar->entry.crc) {
        warn("Checksum of extracted data doesn't match");
        return false;
    }
    return true;
}

ar_archive *ar_open_rar_archive(ar_stream *stream)
{
    char signature[FILE_SIGNATURE_SIZE];
    if (!ar_seek(stream, 0, SEEK_SET))
        return NULL;
    if (ar_read(stream, signature, sizeof(signature)) != sizeof(signature))
        return NULL;
    if (memcmp(signature, "Rar!\x1A\x07\x00", sizeof(signature)) != 0) {
        if (memcmp(signature, "Rar!\x1A\x07\x01", sizeof(signature)) == 0)
            warn("RAR 5 format isn't supported");
        else if (memcmp(signature, "RE~^", 4) == 0)
            warn("Ancient RAR format isn't supported");
        else if (memcmp(signature, "MZ", 2) == 0 || memcmp(signature, "\x7F\x45LF", 4) == 0)
            warn("SFX archives aren't supported");
        return NULL;
    }

    return ar_open_archive(stream, sizeof(ar_archive_rar), rar_close, rar_parse_entry, rar_get_name, rar_uncompress, NULL, FILE_SIGNATURE_SIZE);
}

ar_archive *ar_open_rar_archive_multi(ar_stream *stream, char **paths, int num_paths)
{
    ar_archive *ar = ar_open_rar_archive(stream);
    if (!ar || num_paths <= 1)
        return ar;

    ar_archive_rar *rar = (ar_archive_rar *)ar;

    struct rar_multi_vol_ctx *ctx = (struct rar_multi_vol_ctx *)malloc(sizeof(struct rar_multi_vol_ctx));
    if (!ctx)
        return ar;

    ctx->paths = (char **)malloc(sizeof(char *) * num_paths);
    if (!ctx->paths) {
        free(ctx);
        return ar;
    }

    ctx->original_stream = stream;
    ctx->num_paths        = num_paths;
    ctx->current          = 0;
    ctx->current_opened   = NULL;

    for (int i = 0; i < num_paths; i++) {
        size_t plen = strlen(paths[i]);
        ctx->paths[i] = (char *)malloc(plen + 1);
        if (!ctx->paths[i]) {
            for (int j = 0; j < i; j++)
                free(ctx->paths[j]);
            free(ctx->paths);
            free(ctx);
            return ar;
        }
        memcpy(ctx->paths[i], paths[i], plen + 1);
    }

    rar->next_volume = rar_next_volume;
    rar->volume_ctx  = ctx;
    return ar;
}
