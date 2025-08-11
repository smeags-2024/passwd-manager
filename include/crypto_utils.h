#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>

class CryptoUtils {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key);
    static std::string decrypt(const std::string& ciphertext, const std::string& key);
    
    // Advanced encryption methods
    static std::string encryptChaCha20(const std::string& plaintext, const std::string& key);
    static std::string decryptChaCha20(const std::string& ciphertext, const std::string& key);
    static std::string encryptAESGCM(const std::string& plaintext, const std::string& key);
    static std::string decryptAESGCM(const std::string& ciphertext, const std::string& key);
    
    static std::string generateSalt();
    static std::string generateRandomKey(int length = 32);
    static std::vector<unsigned char> generateRandomBytes(int length);
    static std::string generateSecurePassword(int length = 16, bool includeSymbols = true, bool includeNumbers = true, bool includeUppercase = true, bool includeLowercase = true);
    
    // Encryption-specific password generation
    static std::string generatePasswordForAES(int length = 20);        // Optimized for AES-256
    static std::string generatePasswordForChaCha20(int length = 24);   // Optimized for ChaCha20
    static std::string generatePasswordForGCM(int length = 32);        // Optimized for authenticated encryption
    
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt);
    
    // Password strength analysis
    static int calculatePasswordStrength(const std::string& password);
    static std::string getPasswordStrengthText(int strength);

private:
    // AES encryption methods
    static std::string aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv);
    static std::string aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
    
    // AES-GCM encryption methods
    static std::string aesGcmEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv);
    static std::string aesGcmDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
    
    // ChaCha20-Poly1305 encryption methods
    static std::string chacha20Encrypt(const std::string& plaintext, const std::string& key, const std::string& nonce);
    static std::string chacha20Decrypt(const std::string& ciphertext, const std::string& key, const std::string& nonce);
    
    // Key derivation
    static std::string deriveKey(const std::string& password, const std::string& salt);
    static std::string deriveKeyArgon2(const std::string& password, const std::string& salt); // For ChaCha20
    static std::string deriveKeyScrypt(const std::string& password, const std::string& salt);  // For AES-GCM
    
    // Legacy XOR cipher (fallback)
    static std::string xorCipher(const std::string& data, const std::string& key);
    
    // Base64 encoding/decoding
    static std::string base64Encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base64Decode(const std::string& encoded);
};

#endif // CRYPTO_UTILS_H
