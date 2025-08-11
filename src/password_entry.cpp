#include "password_entry.h"
#include <sstream>
#include <random>
#include <iomanip>
#include <algorithm>

// Base64 encoding functions for safe text storage
std::string simpleBase64Encode(const std::string& input) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}

std::string simpleBase64Decode(const std::string& input) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

void PasswordEntry::generateId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    id = ss.str();
}

std::string PasswordEntry::toString() const {
    std::stringstream ss;
    ss << simpleBase64Encode(id) << "|" << simpleBase64Encode(title) << "|" << simpleBase64Encode(username) << "|" 
       << simpleBase64Encode(password) << "|" << simpleBase64Encode(url) << "|" << simpleBase64Encode(notes) << "|" 
       << created << "|" << modified;
    return ss.str();
}

PasswordEntry PasswordEntry::fromString(const std::string& data) {
    std::stringstream ss(data);
    std::string token;
    PasswordEntry entry;
    
    // Try to decode each field, with fallback for backward compatibility
    auto safeDecode = [](const std::string& encoded) -> std::string {
        try {
            // First try base64 decoding
            std::string decoded = simpleBase64Decode(encoded);
            // Check if the result makes sense (no null bytes in normal positions)
            if (decoded.find('\0') == std::string::npos || decoded.empty()) {
                return decoded;
            }
        } catch (...) {
            // Base64 failed, might be old URL encoding
        }
        
        // Fallback: return the original string if it doesn't contain problematic patterns
        if (encoded.find("%0") == std::string::npos) {
            return encoded;
        }
        
        // If it contains %0 patterns, try to clean it up
        std::string cleaned = encoded;
        size_t pos = 0;
        while ((pos = cleaned.find("%0", pos)) != std::string::npos) {
            if (pos + 2 < cleaned.length()) {
                // Replace %0X with just X
                cleaned.replace(pos, 3, 1, cleaned[pos + 2]);
            }
            pos++;
        }
        return cleaned;
    };
    
    if (std::getline(ss, token, '|')) entry.id = safeDecode(token);
    if (std::getline(ss, token, '|')) entry.title = safeDecode(token);
    if (std::getline(ss, token, '|')) entry.username = safeDecode(token);
    if (std::getline(ss, token, '|')) entry.password = safeDecode(token);
    if (std::getline(ss, token, '|')) entry.url = safeDecode(token);
    if (std::getline(ss, token, '|')) entry.notes = safeDecode(token);
    if (std::getline(ss, token, '|') && !token.empty()) {
        try {
            entry.created = std::stoll(token);
        } catch (const std::exception&) {
            entry.created = std::time(nullptr);
        }
    }
    if (std::getline(ss, token, '|') && !token.empty()) {
        try {
            entry.modified = std::stoll(token);
        } catch (const std::exception&) {
            entry.modified = std::time(nullptr);
        }
    }
    
    // If ID is empty, generate one (for backward compatibility)
    if (entry.id.empty()) {
        entry.generateId();
    }
    
    return entry;
}
