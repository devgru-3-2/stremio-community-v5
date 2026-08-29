#ifndef PINLOCK_H
#define PINLOCK_H

#include <string>

// PBKDF2-HMAC-SHA256 PIN hashing helpers (OpenSSL).
// Used to store/verify a per-profile passcode without storing it in plaintext.

// Random salt as lowercase hex; falls back to a deterministic weak salt if the RNG fails
std::string GenerateSaltHex(std::size_t numBytes = 16);

// Derive a salted hash (hex) of a PIN using PBKDF2-HMAC-SHA256
std::string DerivePBKDF2_SHA256(const std::string &pinUtf8,
                                const std::string &saltHex,
                                int iterations = 150000,
                                std::size_t dkLen = 32);

#endif // PINLOCK_H
