// Package web3auth implements SIWE (Sign-In With Ethereum / EIP-4361) wallet
// authentication for security testing. It creates an ephemeral secp256k1 key
// pair, derives the Ethereum address, constructs a SIWE message, signs it
// using EIP-191 personal_sign, and handles the nonce/verify handshake.
//
// The wallet is purely ephemeral — the private key is generated fresh per scan
// and immediately discarded after the session ends. It is never reused, stored,
// or associated with any real funds.
package web3auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Wallet is an ephemeral Ethereum key pair used only for SIWE probe sessions.
type Wallet struct {
	privateKey *secp256k1.PrivateKey
	Address    string // checksummed hex, e.g. "0xAbCd..."
}

// newEphemeralWallet generates a fresh secp256k1 key pair and derives the
// corresponding Ethereum address. Returns an error only on entropy failure.
func newEphemeralWallet() (*Wallet, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("web3auth: keygen: %w", err)
	}
	addr := pubKeyToAddress(priv.PubKey())
	return &Wallet{privateKey: priv, Address: addr}, nil
}

// pubKeyToAddress derives the Ethereum address from an uncompressed secp256k1
// public key using keccak256(pubkey[1:])[12:] per the Yellow Paper.
func pubKeyToAddress(pub *secp256k1.PublicKey) string {
	// Serialize as uncompressed (65 bytes: 0x04 || X || Y).
	uncompressed := pub.SerializeUncompressed()
	// Drop the 0x04 prefix byte — Ethereum hashes only the X||Y bytes.
	payload := uncompressed[1:]
	h := keccak256(payload)
	// Take the last 20 bytes as the address.
	raw := hex.EncodeToString(h[12:])
	return "0x" + toChecksumAddress(raw)
}

// keccak256 returns the Keccak-256 hash of b.
// Note: Ethereum uses Keccak-256, NOT SHA3-256 (NIST). Go's sha3 package
// exports both; sha3.NewLegacyKeccak256() gives the Keccak variant.
func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// toChecksumAddress applies EIP-55 mixed-case checksum encoding.
func toChecksumAddress(addr string) string {
	addr = strings.ToLower(addr)
	hash := hex.EncodeToString(keccak256([]byte(addr)))
	out := make([]byte, len(addr))
	for i := 0; i < len(addr); i++ {
		if addr[i] >= '0' && addr[i] <= '9' {
			out[i] = addr[i]
		} else if hash[i] >= '8' {
			out[i] = addr[i] - 32 // uppercase
		} else {
			out[i] = addr[i]
		}
	}
	return string(out)
}

// buildSIWEMessage constructs an EIP-4361 Sign-In With Ethereum message.
//
//	domain  — the RFC 3986 authority of the server (e.g. "example.com")
//	address — the checksummed Ethereum address
//	nonce   — server-issued nonce (at least 8 alphanumeric chars per EIP-4361)
//	uri     — the full URI of the resource (e.g. "https://example.com")
func buildSIWEMessage(domain, address, nonce, uri string) string {
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(
		"%s wants you to sign in with your Ethereum account:\n"+
			"%s\n\n"+
			"Beacon security scanner authentication probe.\n\n"+
			"URI: %s\n"+
			"Version: 1\n"+
			"Chain ID: 1\n"+
			"Nonce: %s\n"+
			"Issued At: %s",
		domain, address, uri, nonce, issuedAt,
	)
}

// personalSign signs a SIWE message using EIP-191 personal_sign:
//
//	keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
//
// Returns the 65-byte signature as a 0x-prefixed hex string (r+s+v format).
func (w *Wallet) personalSign(message string) string {
	msgBytes := []byte(message)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msgBytes))
	hash := keccak256(append([]byte(prefix), msgBytes...))

	sig := ecdsa.SignCompact(w.privateKey, hash, false)
	// SignCompact returns [v, r(32), s(32)] — 65 bytes total.
	// Ethereum expects [r(32), s(32), v] so we rotate.
	v := sig[0]
	rs := sig[1:]
	ethSig := append(rs, v)
	return "0x" + hex.EncodeToString(ethSig)
}

// randomNonce returns a random 12-character alphanumeric string suitable for
// use as a SIWE nonce when the server doesn't provide one.
func randomNonce() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:12]
}
