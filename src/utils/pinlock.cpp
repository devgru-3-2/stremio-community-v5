#include "pinlock.h"

#include <vector>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/rand.h>

static std::string BytesToHex(const std::vector<unsigned char> &bytes)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

static std::vector<unsigned char> HexToBytes(const std::string &hex)
{
    std::vector<unsigned char> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int v = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> v;
        out.push_back(static_cast<unsigned char>(v));
    }
    return out;
}

std::string GenerateSaltHex(std::size_t numBytes)
{
    std::vector<unsigned char> buf(numBytes);
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
        // fallback weak salt if RNG fails
        for (size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<unsigned char>(i * 31 + 7);
    }
    return BytesToHex(buf);
}

std::string DerivePBKDF2_SHA256(const std::string &pinUtf8,
                                const std::string &saltHex,
                                int iterations,
                                std::size_t dkLen)
{
    std::vector<unsigned char> dk(dkLen);
    std::vector<unsigned char> salt = HexToBytes(saltHex);
    if (salt.empty()) salt = HexToBytes(GenerateSaltHex());
    int ok = PKCS5_PBKDF2_HMAC(
        pinUtf8.c_str(), static_cast<int>(pinUtf8.size()),
        salt.data(), static_cast<int>(salt.size()),
        iterations, EVP_sha256(), static_cast<int>(dk.size()), dk.data());
    if (ok != 1) return {};
    return BytesToHex(dk);
}
