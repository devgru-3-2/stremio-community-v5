#ifndef PROFILES_H
#define PROFILES_H

#include <string>
#include <vector>
#include <optional>
#include "nlohmann/json.hpp"

// Minimal profile schema for MVP
struct ProfileMeta {
	std::string id;              // stable UUID/string id
	std::string name;            // display name
	bool kids = false;           // kids mode flag
	std::string userDataDir;     // relative path under portable_config/profiles/{id}
	std::optional<std::string> passcodeHash; // optional hashed PIN
	std::optional<std::string> salt;         // optional per-profile salt
};

// Container serialization helpers
struct ProfilesDoc {
	std::vector<ProfileMeta> profiles;
};

// API
// Returns absolute path to portable_config/profiles.json, ensures portable_config exists
std::wstring GetProfilesJsonPath();

// Load profiles.json; returns empty container if file missing/invalid
ProfilesDoc LoadProfiles();

// Write profiles.json atomically; returns true on success
bool SaveProfiles(const ProfilesDoc &doc);

// Utility to create a default directory for a profile under portable_config/profiles/{id}
// Returns absolute directory path; ensures it exists
std::wstring EnsureProfileDataDir(const std::string &id);

// Security helpers (PBKDF2-HMAC-SHA256 via OpenSSL)
std::string GenerateSaltHex(std::size_t numBytes = 16);
std::string DerivePBKDF2_SHA256(const std::string &pinUtf8, const std::string &saltHex, int iterations = 150000, std::size_t dkLen = 32);
bool VerifyPin(const ProfileMeta &meta, const std::string &pinUtf8);
void SetPin(ProfileMeta &meta, const std::string &pinUtf8, int iterations = 150000);

#endif // PROFILES_H


