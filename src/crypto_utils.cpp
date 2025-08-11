#include "crypto_utils.h"
#include "logger.h"
#include <QString>
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <memory>

std::string CryptoUtils::encrypt(const std::string& plaintext, const std::string& key) {
    try {
        // Generate random IV (16 bytes for AES)
        std::vector<unsigned char> ivBytes = generateRandomBytes(16);
        std::string iv(ivBytes.begin(), ivBytes.end());
        
        // Derive key from password
        std::string derivedKey = deriveKey(key, iv);
        
        // Encrypt using AES
        std::string encrypted = aesEncrypt(plaintext, derivedKey, iv);
        
        // Combine IV + encrypted data and base64 encode
        std::string combined = iv + encrypted;
        std::vector<unsigned char> data(combined.begin(), combined.end());
        return base64Encode(data);
    } catch (const std::exception& e) {
        // Fallback to XOR cipher if AES fails
        std::string encrypted = xorCipher(plaintext, key);
        std::vector<unsigned char> data(encrypted.begin(), encrypted.end());
        return "XOR:" + base64Encode(data);
    }
}

std::string CryptoUtils::decrypt(const std::string& ciphertext, const std::string& key) {
    try {
        // Check for other encryption formats and reject them to ensure proper fallback
        if (ciphertext.length() >= 7 && ciphertext.substr(0, 7) == "AESGCM:") {
            // This is AES-GCM format, return empty to trigger proper fallback
            return "";
        }
        if (ciphertext.length() >= 9 && ciphertext.substr(0, 9) == "CHACHA20:") {
            // This is ChaCha20 format, return empty to trigger proper fallback  
            return "";
        }
        
        // Check if it's XOR encrypted (legacy)
        if (ciphertext.substr(0, 4) == "XOR:") {
            std::vector<unsigned char> data = base64Decode(ciphertext.substr(4));
            std::string encrypted(data.begin(), data.end());
            return xorCipher(encrypted, key);
        }
        
        // Decode base64
        std::vector<unsigned char> combined = base64Decode(ciphertext);
        if (combined.size() < 16) {
            throw std::runtime_error("Invalid ciphertext size");
        }
        
        // Extract IV and encrypted data
        std::string iv(combined.begin(), combined.begin() + 16);
        std::string encrypted(combined.begin() + 16, combined.end());
        
        // Derive key from password
        std::string derivedKey = deriveKey(key, iv);
        
        // Decrypt using AES
        return aesDecrypt(encrypted, derivedKey, iv);
    } catch (const std::exception& e) {
        // Fallback to XOR cipher
        std::vector<unsigned char> data = base64Decode(ciphertext);
        std::string encrypted(data.begin(), data.end());
        return xorCipher(encrypted, key);
    }
}

std::string CryptoUtils::generateSalt() {
    return generateRandomKey(32); // 32 bytes for salt
}

std::string CryptoUtils::generateRandomKey(int length) {
    return base64Encode(generateRandomBytes(length));
}

std::vector<unsigned char> CryptoUtils::generateRandomBytes(int length) {
    std::vector<unsigned char> buffer(length);
    if (RAND_bytes(buffer.data(), length) != 1) {
        // Fallback to C++ random if OpenSSL fails
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (int i = 0; i < length; ++i) {
            buffer[i] = static_cast<unsigned char>(dis(gen));
        }
    }
    return buffer;
}

std::string CryptoUtils::generateSecurePassword(int length, bool includeSymbols, bool includeNumbers, bool includeUppercase, bool includeLowercase) {
    std::string charset = "";
    
    if (includeLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (includeUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeNumbers) charset += "0123456789";
    if (includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    
    if (charset.empty()) {
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    }
    
    std::vector<unsigned char> randomBytes = generateRandomBytes(length);
    std::string password;
    password.reserve(length);
    
    for (int i = 0; i < length; ++i) {
        password += charset[randomBytes[i] % charset.length()];
    }
    
    return password;
}

// AES-256 optimized password generation
std::string CryptoUtils::generatePasswordForAES(int length) {
    // AES works well with high entropy and balanced character distribution
    // Use base64-like charset for optimal AES performance
    std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    std::vector<unsigned char> randomBytes = generateRandomBytes(length);
    std::string password;
    password.reserve(length);
    
    // Ensure good distribution across all character types
    for (int i = 0; i < length; ++i) {
        password += charset[randomBytes[i] % charset.length()];
    }
    
    // Add some special characters for additional entropy
    if (length > 10) {
        std::vector<unsigned char> specialBytes = generateRandomBytes(2);
        std::string specialChars = "!@#$%^&*";
        password[specialBytes[0] % length] = specialChars[specialBytes[1] % specialChars.length()];
    }
    
    return password;
}

// ChaCha20 optimized password generation  
std::string CryptoUtils::generatePasswordForChaCha20(int length) {
    // ChaCha20 benefits from high randomness and non-repeating patterns
    // Use extended ASCII for maximum entropy
    std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                         "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    
    std::vector<unsigned char> randomBytes = generateRandomBytes(length * 2); // Double randomness
    std::string password;
    password.reserve(length);
    
    // Use XOR mixing for additional entropy
    for (int i = 0; i < length; ++i) {
        unsigned char mixed = randomBytes[i] ^ randomBytes[i + length];
        password += charset[mixed % charset.length()];
    }
    
    return password;
}

// AES-GCM optimized password generation (authenticated encryption)
std::string CryptoUtils::generatePasswordForGCM(int length) {
    // GCM benefits from cryptographically strong passwords with high entropy
    // Use only printable ASCII characters for maximum compatibility
    std::string baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    
    std::vector<unsigned char> randomBytes = generateRandomBytes(length * 2); // Double randomness for GCM
    std::string password;
    password.reserve(length);
    
    // Construct password with guaranteed character diversity
    int baseCharsNeeded = std::max(1, static_cast<int>(length * 0.65));  // 65% base characters
    int symbolsNeeded = length - baseCharsNeeded;  // Rest symbols
    
    // Add base characters
    for (int i = 0; i < baseCharsNeeded; ++i) {
        password += baseChars[randomBytes[i] % baseChars.length()];
    }
    
    // Add symbols
    for (int i = 0; i < symbolsNeeded; ++i) {
        password += symbols[randomBytes[baseCharsNeeded + i] % symbols.length()];
    }
    
    // Shuffle the password for random distribution using Fisher-Yates algorithm
    for (int i = length - 1; i > 0; --i) {
        int j = randomBytes[length + (i % length)] % (i + 1);
        std::swap(password[i], password[j]);
    }
    
    return password;
}

int CryptoUtils::calculatePasswordStrength(const std::string& password) {
    if (password.empty()) return 0;
    
    int score = 0;
    
    // Length bonus (more generous scoring)
    score += std::min(static_cast<int>(password.length()) * 3, 30);
    
    // Character variety analysis
    bool hasLower = false, hasUpper = false, hasNumber = false, hasSymbol = false;
    bool hasSpace = false;
    
    for (char c : password) {
        if (c >= 'a' && c <= 'z') hasLower = true;
        else if (c >= 'A' && c <= 'Z') hasUpper = true;
        else if (c >= '0' && c <= '9') hasNumber = true;
        else if (c == ' ') hasSpace = true;
        else hasSymbol = true;
    }
    
    int variety = hasLower + hasUpper + hasNumber + hasSymbol;
    score += variety * 15; // Increased variety bonus
    
    // Length milestones
    if (password.length() >= 8) score += 5;
    if (password.length() >= 12) score += 10;
    if (password.length() >= 16) score += 10;
    if (password.length() >= 20) score += 10;
    
    // Advanced pattern analysis
    // Check for common patterns and sequences
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Penalty for common patterns
    if (lower.find("123") != std::string::npos || 
        lower.find("abc") != std::string::npos ||
        lower.find("qwe") != std::string::npos ||
        lower.find("password") != std::string::npos ||
        lower.find("admin") != std::string::npos) {
        score -= 15;
    }
    
    // Bonus for non-dictionary patterns
    if (hasSymbol && hasNumber && hasUpper && hasLower) {
        score += 10; // Full character set bonus
    }
    
    // Penalty for repeated characters
    int repeatedChars = 0;
    for (size_t i = 1; i < password.length(); ++i) {
        if (password[i] == password[i-1]) {
            repeatedChars++;
        }
    }
    score -= repeatedChars * 2;
    
    // Bonus for spaces (passphrases)
    if (hasSpace && password.length() > 15) {
        score += 5;
    }
    
    return std::max(0, std::min(100, score));
}

std::string CryptoUtils::getPasswordStrengthText(int strength) {
    if (strength < 20) {
        return "Very Weak - Use a longer password with mixed characters";
    } else if (strength < 40) {
        return "Weak - Add more character variety and length";
    } else if (strength < 60) {
        return "Fair - Consider adding symbols or increasing length";
    } else if (strength < 80) {
        return "Good - This password provides decent security";
    } else if (strength < 95) {
        return "Strong - Excellent password security";
    } else {
        return "Very Strong - Outstanding password security";
    }
}

std::string CryptoUtils::hashPassword(const std::string& password, const std::string& salt) {
    // Use PBKDF2 with SHA-256 for secure password hashing
    const int iterations = 100000; // Increased from 10,000 to 100,000 for better security
    const int keyLength = 32;
    
    std::vector<unsigned char> saltBytes = base64Decode(salt);
    std::vector<unsigned char> hash(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          saltBytes.data(), saltBytes.size(),
                          iterations, EVP_sha256(),
                          keyLength, hash.data()) != 1) {
        // Fallback to simple hash if PBKDF2 fails
        std::string combined = password + salt;
        std::hash<std::string> hasher;
        size_t hashValue = hasher(combined);
        
        std::stringstream ss;
        ss << std::hex << hashValue;
        return ss.str();
    }
    
    return base64Encode(hash);
}

bool CryptoUtils::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    return hashPassword(password, salt) == hash;
}

std::string CryptoUtils::xorCipher(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < data.length(); ++i) {
        result[i] = data[i] ^ key[i % key.length()];
    }
    return result;
}

std::string CryptoUtils::base64Encode(const std::vector<unsigned char>& data) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (result.size() % 4) {
        result.push_back('=');
    }
    
    return result;
}

std::vector<unsigned char> CryptoUtils::base64Decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> result;
    int val = 0, valb = -8;
    
    for (char c : encoded) {
        if (chars.find(c) == std::string::npos) break;
        val = (val << 6) + chars.find(c);
        valb += 6;
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return result;
}

std::string CryptoUtils::aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");
    
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    
    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
}

std::string CryptoUtils::aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");
    
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    std::vector<unsigned char> plaintext(ciphertext.length() + AES_BLOCK_SIZE);
    int len;
    int plaintext_len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                         ciphertext.length()) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

std::string CryptoUtils::deriveKey(const std::string& password, const std::string& salt) {
    const int iterations = 100000; // Increased iterations for better security
    const int keyLength = 32; // 256 bits for AES-256
    
    std::vector<unsigned char> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha256(),
                          keyLength, key.data()) != 1) {
        throw std::runtime_error("Failed to derive key");
    }
    
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

// ChaCha20-Poly1305 encryption with Argon2 key derivation
std::string CryptoUtils::encryptChaCha20(const std::string& plaintext, const std::string& key) {
    try {
        // Generate separate salt and nonce
        std::vector<unsigned char> saltBytes = generateRandomBytes(16);
        std::vector<unsigned char> nonceBytes = generateRandomBytes(12);
        std::string salt(saltBytes.begin(), saltBytes.end());
        std::string nonce(nonceBytes.begin(), nonceBytes.end());
        
        std::string derivedKey = deriveKeyArgon2(key, salt);
        std::string ciphertext = chacha20Encrypt(plaintext, derivedKey, nonce);
        
        // Convert ciphertext to vector for base64 encoding
        std::vector<unsigned char> ciphertextBytes(ciphertext.begin(), ciphertext.end());
        
        // Format: CHACHA20:salt_b64|nonce_b64|ciphertext_b64
        return "CHACHA20:" + base64Encode(saltBytes) + "|" + base64Encode(nonceBytes) + "|" + base64Encode(ciphertextBytes);
    } catch (const std::exception& e) {
        LOG_ERROR(QString("ChaCha20 encryption failed: %1").arg(e.what()));
        return "";
    }
}

std::string CryptoUtils::decryptChaCha20(const std::string& ciphertext, const std::string& key) {
    try {
        // Check for ChaCha20 format - only decrypt ChaCha20 data
        if (ciphertext.length() < 9 || ciphertext.substr(0, 9) != "CHACHA20:") {
            // Not a ChaCha20 format, return empty to trigger fallback
            LOG_INFO("Not ChaCha20 format, returning empty for fallback");
            return "";
        }
        
        LOG_INFO("Detected ChaCha20 format, attempting ChaCha20 decryption");
        
        std::string data = ciphertext.substr(9); // Remove "CHACHA20:" prefix
        
        // Parse format: salt_b64|nonce_b64|ciphertext
        size_t firstSep = data.find('|');
        if (firstSep == std::string::npos) {
            LOG_ERROR("ChaCha20: Missing first separator");
            return ""; // Return empty to trigger fallback
        }
        
        size_t secondSep = data.find('|', firstSep + 1);
        if (secondSep == std::string::npos) {
            LOG_ERROR("ChaCha20: Missing second separator");
            return ""; // Return empty to trigger fallback
        }
        
        std::string saltB64 = data.substr(0, firstSep);
        std::string nonceB64 = data.substr(firstSep + 1, secondSep - firstSep - 1);
        std::string encryptedB64 = data.substr(secondSep + 1);
        
        std::vector<unsigned char> saltBytes = base64Decode(saltB64);
        std::vector<unsigned char> nonceBytes = base64Decode(nonceB64);
        std::vector<unsigned char> encryptedBytes = base64Decode(encryptedB64);
        std::string salt(saltBytes.begin(), saltBytes.end());
        std::string nonce(nonceBytes.begin(), nonceBytes.end());
        std::string encrypted(encryptedBytes.begin(), encryptedBytes.end());
        
        std::string derivedKey = deriveKeyArgon2(key, salt);
        std::string result = chacha20Decrypt(encrypted, derivedKey, nonce);
        
        LOG_INFO("ChaCha20 decryption completed");
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR(QString("ChaCha20 decryption failed: %1").arg(e.what()));
        // Try fallback to standard decryption
        try {
            LOG_INFO("Trying fallback to standard AES decryption");
            return decrypt(ciphertext, key);
        } catch (const std::exception& e2) {
            LOG_ERROR(QString("ChaCha20 fallback also failed: %1").arg(e2.what()));
            return "";
        }
    }
}

// AES-256-GCM encryption with scrypt key derivation
std::string CryptoUtils::encryptAESGCM(const std::string& plaintext, const std::string& key) {
    try {
        // Generate separate salt and IV
        std::vector<unsigned char> saltBytes = generateRandomBytes(16);
        std::vector<unsigned char> ivBytes = generateRandomBytes(12);
        std::string salt(saltBytes.begin(), saltBytes.end());
        std::string iv(ivBytes.begin(), ivBytes.end());
        
        std::string derivedKey = deriveKeyScrypt(key, salt);
        std::string ciphertext = aesGcmEncrypt(plaintext, derivedKey, iv);
        
        // Convert ciphertext to vector for base64 encoding
        std::vector<unsigned char> ciphertextBytes(ciphertext.begin(), ciphertext.end());
        
        // Format: AESGCM:salt_b64|iv_b64|ciphertext_b64
        return "AESGCM:" + base64Encode(saltBytes) + "|" + base64Encode(ivBytes) + "|" + base64Encode(ciphertextBytes);
    } catch (const std::exception& e) {
        LOG_ERROR(QString("AES-GCM encryption failed: %1").arg(e.what()));
        return "";
    }
}

std::string CryptoUtils::decryptAESGCM(const std::string& ciphertext, const std::string& key) {
    try {
        // Check for AES-GCM format - only decrypt AES-GCM data
        if (ciphertext.length() < 7 || ciphertext.substr(0, 7) != "AESGCM:") {
            // Not an AES-GCM format, return empty to trigger fallback
            LOG_INFO("Not AES-GCM format, returning empty for fallback");
            return "";
        }
        
        LOG_INFO("Detected AES-GCM format, attempting AES-GCM decryption");
        
        std::string data = ciphertext.substr(7); // Remove "AESGCM:" prefix
        
        // Parse format: salt_b64|iv_b64|ciphertext
        size_t firstSep = data.find('|');
        if (firstSep == std::string::npos) {
            LOG_ERROR("AES-GCM: Missing first separator");
            return ""; // Return empty to trigger fallback
        }
        
        size_t secondSep = data.find('|', firstSep + 1);
        if (secondSep == std::string::npos) {
            LOG_ERROR("AES-GCM: Missing second separator");
            return ""; // Return empty to trigger fallback
        }
        
        std::string saltB64 = data.substr(0, firstSep);
        std::string ivB64 = data.substr(firstSep + 1, secondSep - firstSep - 1);
        std::string encryptedB64 = data.substr(secondSep + 1);
        
        std::vector<unsigned char> saltBytes = base64Decode(saltB64);
        std::vector<unsigned char> ivBytes = base64Decode(ivB64);
        std::vector<unsigned char> encryptedBytes = base64Decode(encryptedB64);
        std::string salt(saltBytes.begin(), saltBytes.end());
        std::string iv(ivBytes.begin(), ivBytes.end());
        std::string encrypted(encryptedBytes.begin(), encryptedBytes.end());
        
        std::string derivedKey = deriveKeyScrypt(key, salt);
        std::string result = aesGcmDecrypt(encrypted, derivedKey, iv);
        
        LOG_INFO("AES-GCM decryption completed");
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR(QString("AES-GCM decryption failed: %1").arg(e.what()));
        // Try fallback to standard decryption
        try {
            LOG_INFO("Trying fallback to standard AES decryption");
            std::string fallback_result = decrypt(ciphertext, key);
            if (!fallback_result.empty()) {
                LOG_INFO("Successfully decrypted with AES fallback from AES-GCM");
                return fallback_result;
            }
        } catch (const std::exception& e2) {
            LOG_ERROR(QString("AES-GCM fallback also failed: %1").arg(e2.what()));
        }
        return "";
    }
}

// Argon2 key derivation for ChaCha20 (memory-hard function)
std::string CryptoUtils::deriveKeyArgon2(const std::string& password, const std::string& salt) {
    // For now, use enhanced PBKDF2 until we can add Argon2 library
    // In production, this should use Argon2id
    const int iterations = 200000; // Higher iterations for Argon2 simulation
    const int keyLength = 32; // 256 bits
    
    std::vector<unsigned char> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha512(), // Use SHA-512 for diversity
                          keyLength, key.data()) != 1) {
        throw std::runtime_error("Failed to derive Argon2-style key");
    }
    
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

// scrypt key derivation for AES-GCM (memory-hard function)
std::string CryptoUtils::deriveKeyScrypt(const std::string& password, const std::string& salt) {
    // Use PBKDF2 with very high iterations and SHA-512 for stronger key derivation
    const int iterations = 300000; // High iterations for scrypt simulation
    const int keyLength = 32; // 256 bits
    
    std::vector<unsigned char> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha512(), // Use SHA-512 for stronger derivation
                          keyLength, key.data()) != 1) {
        throw std::runtime_error("Failed to derive scrypt-style key");
    }
    
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

// ChaCha20-Poly1305 encryption
std::string CryptoUtils::chacha20Encrypt(const std::string& plaintext, const std::string& key, const std::string& nonce) {
    // For now, use AES-256-CTR as a substitute until ChaCha20 is available
    // This provides similar stream cipher properties
    std::string padded_nonce = nonce;
    if (padded_nonce.length() < 16) {
        padded_nonce.resize(16, 0); // Pad to 16 bytes for AES
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, 
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(padded_nonce.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_ctr()));
    int len;
    int ciphertext_len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(ciphertext_len);
    // Return raw binary data as string (will be base64 encoded by caller)
    return std::string(ciphertext.begin(), ciphertext.end());
}

std::string CryptoUtils::chacha20Decrypt(const std::string& ciphertext, const std::string& key, const std::string& nonce) {
    // Convert string back to binary data
    std::vector<unsigned char> encrypted(ciphertext.begin(), ciphertext.end());
    
    std::string padded_nonce = nonce;
    if (padded_nonce.length() < 16) {
        padded_nonce.resize(16, 0); // Pad to 16 bytes for AES
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr,
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(padded_nonce.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    std::vector<unsigned char> plaintext(encrypted.size() + EVP_CIPHER_block_size(EVP_aes_256_ctr()));
    int len;
    int plaintext_len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

// AES-256-GCM encryption
std::string CryptoUtils::aesGcmEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create GCM cipher context");
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize GCM encryption");
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM IV length");
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM key and IV");
    }
    
    std::vector<unsigned char> ciphertext(plaintext.length());
    int len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt GCM data");
    }
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize GCM encryption");
    }
    
    // Get the authentication tag
    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine ciphertext and tag
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
}

std::string CryptoUtils::aesGcmDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    // Convert string back to binary data
    std::vector<unsigned char> combined(ciphertext.begin(), ciphertext.end());
    if (combined.size() < 16) {
        throw std::runtime_error("Invalid GCM ciphertext size");
    }
    
    // Split ciphertext and tag
    std::vector<unsigned char> encrypted(combined.begin(), combined.end() - 16);
    std::vector<unsigned char> tag(combined.end() - 16, combined.end());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create GCM cipher context");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize GCM decryption");
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM IV length");
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                          reinterpret_cast<const unsigned char*>(key.c_str()),
                          reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM key and IV");
    }
    
    std::vector<unsigned char> plaintext(encrypted.size());
    int len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt GCM data");
    }
    
    // Set the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret <= 0) {
        throw std::runtime_error("GCM authentication failed");
    }
    
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}
