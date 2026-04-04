package ntlm

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseType2(t *testing.T) {
	// Build a minimal Type 2 message with known values.
	msg := make([]byte, 56)
	copy(msg, "NTLMSSP\x00")
	msg[8] = 0x02 // Type 2

	// Target name: "CORP" at offset 48, length 8 (UTF-16LE).
	targetName := encodeUTF16LE("CORP")
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName))) // length
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName))) // max length
	binary.LittleEndian.PutUint32(msg[16:20], 48)                     // offset

	// No target info in this minimal test.
	msg = append(msg[:48], targetName...)

	info := parseType2(msg)
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info["domain"] != "CORP" {
		t.Errorf("domain = %q, want CORP", info["domain"])
	}
}

func TestParseType2WithTargetInfo(t *testing.T) {
	// Build a Type 2 message with target info pairs.
	msg := make([]byte, 56)
	copy(msg, "NTLMSSP\x00")
	msg[8] = 0x02 // Type 2

	// Target name at offset 56.
	targetName := encodeUTF16LE("CORP")
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], 56)

	// Flags.
	binary.LittleEndian.PutUint32(msg[20:24], 0x00028233)

	// Challenge (8 bytes at offset 24).
	copy(msg[24:32], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	// Reserved (8 bytes at offset 32).

	// Target info at offset = 56 + len(targetName).
	tiOffset := 56 + len(targetName)
	// Build target info: MsvAvNbDomainName="CORP", MsvAvDnsDomainName="corp.local", MsvAvEOL.
	var ti []byte
	domainName := encodeUTF16LE("CORP")
	ti = appendAVPair(ti, 0x0002, domainName) // NbDomainName
	dnsDomain := encodeUTF16LE("corp.local")
	ti = appendAVPair(ti, 0x0003, dnsDomain) // DnsDomainName
	serverName := encodeUTF16LE("DC01")
	ti = appendAVPair(ti, 0x0001, serverName) // NbComputerName
	ti = appendAVPair(ti, 0x0000, nil)         // EOL

	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(ti))) // TI length
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(ti))) // TI max length
	binary.LittleEndian.PutUint32(msg[44:48], uint32(tiOffset))

	msg = append(msg[:56], targetName...)
	msg = append(msg, ti...)

	info := parseType2(msg)
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info["domain"] != "CORP" {
		t.Errorf("domain = %q, want CORP", info["domain"])
	}
	if info["dns_domain"] != "corp.local" {
		t.Errorf("dns_domain = %q, want corp.local", info["dns_domain"])
	}
	if info["server"] != "DC01" {
		t.Errorf("server = %q, want DC01", info["server"])
	}
}

func TestParseType2Nil(t *testing.T) {
	// Too short.
	if parseType2([]byte{1, 2, 3}) != nil {
		t.Error("expected nil for short input")
	}
	// Wrong signature.
	bad := make([]byte, 32)
	copy(bad, "BADBADBAD")
	if parseType2(bad) != nil {
		t.Error("expected nil for bad signature")
	}
}

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func appendAVPair(ti []byte, avID uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[0:2], avID)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return append(ti, pair...)
}
