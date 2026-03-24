// siws.go implements Sign In With Solana (SIWS) — the Solana equivalent of SIWE.
//
// Solana uses Ed25519 (not secp256k1) and base58-encoded public keys as addresses.
// The signing call is a raw Ed25519 sign of the message bytes with no EIP-191 prefix.
// The SIWS message format mirrors SIWE (EIP-4361) but references the Solana chain.
//
// All wallets that use Phantom's Solana integration (Phantom, Solflare, Backpack,
// Brave Wallet in Solana mode) implement this signing scheme.
package web3auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// base58Alphabet is the Bitcoin/Solana base58 character set.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes a byte slice into a base58 string.
func base58Encode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	result := []byte{}
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append([]byte{base58Alphabet[mod.Int64()]}, result...)
	}
	// Leading zero bytes → leading '1' characters.
	for _, b := range input {
		if b == 0 {
			result = append([]byte{'1'}, result...)
		} else {
			break
		}
	}
	return string(result)
}

// SolanaWallet is an ephemeral Ed25519 key pair for SIWS probe sessions.
type SolanaWallet struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	// Address is the base58-encoded 32-byte public key — Solana's address format.
	Address string
}

// newEphemeralSolanaWallet generates a fresh Ed25519 key pair.
// The address is the base58-encoded public key, identical to how Phantom
// and all Solana wallets derive their public address.
func newEphemeralSolanaWallet() (*SolanaWallet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("web3auth: solana keygen: %w", err)
	}
	return &SolanaWallet{
		privateKey: priv,
		publicKey:  pub,
		Address:    base58Encode(pub),
	}, nil
}

// buildSIWSMessage constructs a Sign In With Solana message in the SIWE-compatible
// format used by Phantom and most Solana dApps. The message is then signed with
// Ed25519.
func buildSIWSMessage(domain, address, nonce, uri string) string {
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(
		"%s wants you to sign in with your Solana account:\n"+
			"%s\n\n"+
			"Beacon security scanner authentication probe.\n\n"+
			"URI: %s\n"+
			"Version: 1\n"+
			"Chain ID: solana:mainnet\n"+
			"Nonce: %s\n"+
			"Issued At: %s",
		domain, address, uri, nonce, issuedAt,
	)
}

// sign signs a SIWS message using raw Ed25519.
// Unlike Ethereum's EIP-191 personal_sign, Solana signs the message bytes directly
// with no prefix. Returns the 64-byte signature as a 0x-prefixed hex string
// (hex is used here for easy JSON serialization — some backends also accept base58).
func (w *SolanaWallet) sign(message string) string {
	sig := ed25519.Sign(w.privateKey, []byte(message))
	return "0x" + hex.EncodeToString(sig)
}

// signBase58 returns the signature as a base58-encoded string (the format most
// Solana backends expect, e.g., Phantom's sendTransaction response).
func (w *SolanaWallet) signBase58(message string) string {
	sig := ed25519.Sign(w.privateKey, []byte(message))
	return base58Encode(sig)
}
