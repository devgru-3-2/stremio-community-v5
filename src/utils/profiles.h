#ifndef PROFILES_H
#define PROFILES_H

#include <string>
#include <vector>
#include "nlohmann/json.hpp"

// A local profile isolates Stremio sessions (cookies, login, library, config)
// by granting each profile its own WebView2 user-data folder.
struct ProfileMeta {
    std::string id;          // stable id, used as the folder name under portable_config/profiles
    std::string name;        // display name
    std::string userDataDir; // relative path, e.g. "profiles/<id>"
};

struct ProfilesDoc {
    std::vector<ProfileMeta> profiles;
};

// Absolute path to portable_config/profiles.json (ensures portable_config exists)
std::wstring GetProfilesJsonPath();

// Load profiles.json; returns an empty doc if missing/invalid
ProfilesDoc LoadProfiles();

// Write profiles.json atomically (temp file + replace); true on success
bool SaveProfiles(const ProfilesDoc &doc);

// Ensure the profile data directory exists under portable_config/profiles/<id>;
// returns the absolute directory path
std::wstring EnsureProfileDataDir(const std::string &id);

#endif // PROFILES_H
