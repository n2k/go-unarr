// gen_multivol generates a minimal valid RAR4 multi-volume archive for use in
// unit tests.  Run once with:  go run ./testdata/gen_multivol/
//
// Output files written to testdata/:
//   test_multivol.rar   (volume 0)
//   test_multivol.r00   (volume 1)
//
// The archived file is named "multivol" and contains 30720 bytes where every
// byte equals its position modulo 256 (i.e. bytes 0x00..0xFF repeated 120×).
// The content is split so that the first 20000 bytes land in volume 0 and the
// remaining 10720 bytes land in volume 1.
package main

import (
	"encoding/binary"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// ---- RAR4 constants ---------------------------------------------------------

const (
	rarSig = "\x52\x61\x72\x21\x1a\x07\x00"

	typeMainHeader = 0x73
	typeFileEntry  = 0x74
	typeEOA        = 0x7b

	mhdVolume      = 0x0001
	mhdFirstVolume = 0x0100

	lhdSplitBefore = 0x0001
	lhdSplitAfter  = 0x0002
	lhdLongBlock   = 0x8000
)

// ---- helpers ----------------------------------------------------------------

func crc32Std(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}

// headerCRC16 computes the RAR header CRC: low 16 bits of CRC32 starting from
// byte 2 (right after the 2-byte CRC field itself).
func headerCRC16(header []byte) uint16 {
	return uint16(crc32Std(header[2:]) & 0xffff)
}

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}
func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---- RAR4 block builders ----------------------------------------------------

func mainHeader(flags uint16) []byte {
	hdr := make([]byte, 13)
	hdr[2] = typeMainHeader
	binary.LittleEndian.PutUint16(hdr[3:], flags)
	binary.LittleEndian.PutUint16(hdr[5:], 13) // header size
	// bytes 7..12: reserved (already zero)
	binary.LittleEndian.PutUint16(hdr[0:], headerCRC16(hdr))
	return hdr
}

// fileHeader builds a RAR4 file entry header.
//   name       archived filename
//   packSize   bytes of compressed data in this volume
//   unpSize    total uncompressed size (first volume) or remainder (continuation)
//   fileCRC    CRC32 of the complete uncompressed content
//   flags      LHD_ flags (LHD_LONG_BLOCK is always OR-ed in automatically)
func fileHeader(name string, packSize, unpSize uint32, fileCRC uint32, flags uint16) []byte {
	nameBytes := []byte(name)
	nameLen := uint16(len(nameBytes))

	// Fixed fields after the 7-byte base (type,flags,size) and 4-byte pack_size:
	// unp_size(4), host_os(1), file_crc(4), ftime(4), unp_ver(1), method(1),
	// name_size(2), attr(4) → 21 bytes
	// + name

	const baseAfterCRC = 2 + 1 + 2 + 2 + 4 // CRC(2)+type(1)+flags(2)+size(2)+packsize(4)
	headSize := uint16(baseAfterCRC + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + int(nameLen))

	// DOS timestamp 2016-11-22 00:00:00 (same as existing test archives)
	// year   = 2016-1980 = 36 → bits 15..9
	// month  = 11        → bits 8..5
	// day    = 22        → bits 4..0
	// hour   = 0         → bits 31..27
	// minute = 0         → bits 26..21
	// second = 0         → bits 20..16
	const dosDate = uint32((36 << 25) | (11 << 21) | (22 << 16))

	hdr := join(
		make([]byte, 2),        // CRC16 placeholder
		[]byte{typeFileEntry},  // type
		le16(flags|lhdLongBlock), // flags (always set LHD_LONG_BLOCK)
		le16(headSize),         // HEAD_SIZE
		le32(packSize),         // PACK_SIZE (low 32)
		le32(unpSize),          // UNP_SIZE (low 32)
		[]byte{0},              // HOST_OS (0 = MS-DOS)
		le32(fileCRC),          // FILE_CRC
		le32(dosDate),          // FTIME
		[]byte{20},             // UNP_VER (20 = v2.0)
		[]byte{0x30},           // METHOD (0x30 = store)
		le16(nameLen),          // NAME_SIZE
		le32(0),                // ATTR
		nameBytes,              // NAME
	)
	binary.LittleEndian.PutUint16(hdr[0:], headerCRC16(hdr))
	return hdr
}

func eoaHeader() []byte {
	hdr := []byte{0, 0, typeEOA, 0x00, 0x00, 7, 0}
	binary.LittleEndian.PutUint16(hdr[0:], headerCRC16(hdr))
	return hdr
}

// ---- main -------------------------------------------------------------------

func main() {
	// Determine testdata directory relative to this file.
	_, thisFile, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(thisFile), "..")

	// Build the 30720-byte content: bytes 0x00..0xFF repeated 120 times.
	const contentSize = 30720
	content := make([]byte, contentSize)
	for i := range content {
		content[i] = byte(i % 256)
	}
	fileCRC := crc32Std(content)

	const split = 20000 // bytes in volume 0
	vol0Data := content[:split]
	vol1Data := content[split:]

	name := "multivol"

	// ── Volume 0 ─────────────────────────────────────────────────────────────
	vol0 := join(
		[]byte(rarSig),
		mainHeader(mhdVolume|mhdFirstVolume),
		fileHeader(name, uint32(len(vol0Data)), uint32(contentSize), fileCRC, lhdSplitAfter),
		vol0Data,
	)
	write(filepath.Join(testdataDir, "test_multivol.rar"), vol0)

	// ── Volume 1 (last) ───────────────────────────────────────────────────────
	vol1 := join(
		[]byte(rarSig),
		mainHeader(mhdVolume),
		fileHeader(name, uint32(len(vol1Data)), uint32(len(vol1Data)), fileCRC, lhdSplitBefore),
		vol1Data,
		eoaHeader(),
	)
	write(filepath.Join(testdataDir, "test_multivol.r00"), vol1)

	log.Printf("wrote test_multivol.rar (%d bytes) and test_multivol.r00 (%d bytes)",
		len(vol0), len(vol1))
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
