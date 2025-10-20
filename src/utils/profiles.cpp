#include "profiles.h"

#include <windows.h>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <iomanip>
#include "../core/globals.h"
#include "helpers.h"
// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>

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
	if(!f) return false;
	f.write(content.data(), static_cast<std::streamsize>(content.size()));
	return static_cast<bool>(f);
}

static ProfilesDoc ParseProfilesJson(const std::string &raw)
{
	ProfilesDoc out;
	try {
		json j = json::parse(raw);
		if (j.contains("profiles") && j["profiles"].is_array()) {
			for (const auto &p : j["profiles"]) {
				ProfileMeta m;
				if (p.contains("id") && p["id"].is_string()) m.id = p["id"].get<std::string>();
				if (p.contains("name") && p["name"].is_string()) m.name = p["name"].get<std::string>();
				if (p.contains("kids") && p["kids"].is_boolean()) m.kids = p["kids"].get<bool>();
				if (p.contains("userDataDir") && p["userDataDir"].is_string()) m.userDataDir = p["userDataDir"].get<std::string>();
				if (p.contains("passcodeHash") && p["passcodeHash"].is_string()) m.passcodeHash = p["passcodeHash"].get<std::string>();
				if (p.contains("salt") && p["salt"].is_string()) m.salt = p["salt"].get<std::string>();
				if (!m.id.empty()) out.profiles.push_back(std::move(m));
			}
		}
	} catch(...) {
		// ignore malformed content, return empty doc
	}
	return out;
}

static std::string SerializeProfilesJson(const ProfilesDoc &doc)
{
	json j;
	json arr = json::array();
	for (const auto &m : doc.profiles) {
		json p;
		p["id"] = m.id;
		p["name"] = m.name;
		p["kids"] = m.kids;
		p["userDataDir"] = m.userDataDir;
		if (m.passcodeHash.has_value()) p["passcodeHash"] = *m.passcodeHash;
		if (m.salt.has_value()) p["salt"] = *m.salt;
		arr.push_back(std::move(p));
	}
	j["profiles"] = std::move(arr);
	return j.dump(2);
}

ProfilesDoc LoadProfiles()
{
	std::wstring path = GetProfilesJsonPath();
	std::string raw;
	if (!ReadFileUtf8(path, raw)) {
		return ProfilesDoc{}; // missing is fine
	}
	return ParseProfilesJson(raw);
}

bool SaveProfiles(const ProfilesDoc &doc)
{
	std::wstring path = GetProfilesJsonPath();
	std::string content = SerializeProfilesJson(doc);
	// Simple atomic-ish write: write to temp then replace
	std::wstring tmp = path + L".tmp";
	if (!WriteTextFileUtf8(tmp, content)) return false;
	// ReplaceFile is Windows-specific and preserves metadata when possible
	if (!ReplaceFileW(path.c_str(), tmp.c_str(), nullptr, REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
		// Fallback: delete target and rename
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
	std::wstring wId = Utf8ToWstring(id);
	std::filesystem::path p = std::filesystem::path(base) / L"profiles" / wId;
	std::error_code ec;
	std::filesystem::create_directories(p, ec);
	return p.wstring();
}

// ---- Security helpers
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

std::string DerivePBKDF2_SHA256(const std::string &pinUtf8, const std::string &saltHex, int iterations, std::size_t dkLen)
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

bool VerifyPin(const ProfileMeta &meta, const std::string &pinUtf8)
{
	if (!meta.passcodeHash.has_value() || !meta.salt.has_value()) return false;
	std::string derived = DerivePBKDF2_SHA256(pinUtf8, *meta.salt);
	return !derived.empty() && derived == *meta.passcodeHash;
}

void SetPin(ProfileMeta &meta, const std::string &pinUtf8, int iterations)
{
	std::string salt = GenerateSaltHex();
	std::string hash = DerivePBKDF2_SHA256(pinUtf8, salt, iterations);
	meta.salt = salt;
	meta.passcodeHash = hash;
}


