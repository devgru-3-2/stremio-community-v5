#include "profiles.h"

#include <windows.h>
#include <fstream>
#include <filesystem>

#include "../core/globals.h"
#include "helpers.h"
#include "pinlock.h"

using json = nlohmann::json;

static std::wstring GetPortableConfigDir()
{
    std::wstring exeDir = GetExeDirectory();
    std::wstring pcDir  = exeDir + L"\\portable_config";
    CreateDirectoryW(pcDir.c_str(), nullptr);
    return pcDir;
}

std::wstring GetProfilesJsonPath()
{
    return GetPortableConfigDir() + L"\\profiles.json";
}

static bool WriteTextFileUtf8(const std::wstring &path, const std::string &content)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    return static_cast<bool>(f);
}

static ProfilesDoc ParseProfilesJson(const std::string &raw)
{
    ProfilesDoc out;
    try {
        json j = json::parse(raw);
        if (!j.contains("profiles") || !j["profiles"].is_array()) return out;
        for (const auto &p : j["profiles"]) {
            ProfileMeta m;
            if (p.contains("id") && p["id"].is_string())          m.id = p["id"].get<std::string>();
            if (p.contains("name") && p["name"].is_string())      m.name = p["name"].get<std::string>();
            if (p.contains("userDataDir") && p["userDataDir"].is_string()) m.userDataDir = p["userDataDir"].get<std::string>();
            if (p.contains("kids") && p["kids"].is_boolean())     m.kids = p["kids"].get<bool>();
            if (p.contains("passcodeHash") && p["passcodeHash"].is_string()) m.passcodeHash = p["passcodeHash"].get<std::string>();
            if (p.contains("salt") && p["salt"].is_string())      m.salt = p["salt"].get<std::string>();
            if (!m.id.empty()) out.profiles.push_back(std::move(m));
        }
    } catch (...) {
        // ignore malformed content, return empty doc
    }
    return out;
}

static std::string SerializeProfilesJson(const ProfilesDoc &doc)
{
    json arr = json::array();
    for (const auto &m : doc.profiles) {
        json p;
        p["id"]          = m.id;
        p["name"]        = m.name;
        p["userDataDir"] = m.userDataDir;
        p["kids"]        = m.kids;
        if (m.passcodeHash.has_value()) p["passcodeHash"] = *m.passcodeHash;
        if (m.salt.has_value())         p["salt"]         = *m.salt;
        arr.push_back(std::move(p));
    }
    json j;
    j["profiles"] = std::move(arr);
    return j.dump(2);
}

ProfilesDoc LoadProfiles()
{
    std::wstring path = GetProfilesJsonPath();
    std::string raw;
    if (!ReadFileUtf8(path, raw)) return ProfilesDoc{}; // missing is fine
    return ParseProfilesJson(raw);
}

bool SaveProfiles(const ProfilesDoc &doc)
{
    std::wstring path = GetProfilesJsonPath();
    std::wstring tmp  = path + L".tmp";
    if (!WriteTextFileUtf8(tmp, SerializeProfilesJson(doc))) return false;

    // Atomic-ish replace; fall back to delete+rename
    if (!ReplaceFileW(path.c_str(), tmp.c_str(), nullptr,
                      REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
        DeleteFileW(path.c_str());
        if (_wrename(tmp.c_str(), path.c_str()) != 0) {
            DeleteFileW(tmp.c_str());
            return false;
        }
    }
    return true;
}

std::wstring EnsureProfileDataDir(const std::string &id)
{
    std::wstring base = GetPortableConfigDir();
    std::wstring wId  = Utf8ToWstring(id);
    std::filesystem::path p = std::filesystem::path(base) / L"profiles" / wId;
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    return p.wstring();
}

void SetPin(ProfileMeta &meta, const std::string &pinUtf8)
{
    if (pinUtf8.empty()) {
        meta.passcodeHash.reset();
        meta.salt.reset();
        return;
    }
    std::string salt = GenerateSaltHex();
    meta.salt         = salt;
    meta.passcodeHash = DerivePBKDF2_SHA256(pinUtf8, salt);
}

bool VerifyPin(const ProfileMeta &meta, const std::string &pinUtf8)
{
    if (!meta.passcodeHash.has_value() || !meta.salt.has_value()) return false;
    std::string derived = DerivePBKDF2_SHA256(pinUtf8, *meta.salt);
    return !derived.empty() && derived == *meta.passcodeHash;
}
