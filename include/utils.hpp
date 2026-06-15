#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <memory>
#include "bigmath.hpp"
#include "rsa.hpp"

// Helper utilities for working with RSA
class RSAUtils {
public:

    // Converts a string to a byte vector
    static std::vector<uint8_t> stringToBytes(const std::string& str);

    // Converts a byte vector to a string
    static std::string bytesToString(const std::vector<uint8_t>& bytes);

    // Converts a string to a number for encryption
    static std::shared_ptr<BigInt> stringToBigInt(const std::string& str);

    // Converts a number to a string after decryption
    static std::string bigIntToString(const BigInt& num);

    // Splits a large message into blocks that can be encrypted
    static std::vector<std::vector<uint8_t>> splitMessage(const std::vector<uint8_t>& message, size_t maxBlockSize);

    // Joins blocks into one message
    static std::vector<uint8_t> joinBlocks(const std::vector<std::vector<uint8_t>>& blocks);

    // Calculates the maximum block size for a given modulus n
    static size_t calculateMaxBlockSize(const BigInt& n);

    // Encrypts a string using the public key
    static std::vector<std::shared_ptr<BigInt>> encryptString(const std::string& message, const RSA::PublicKey& pubKey);

    // Decrypts a vector of numbers into a string
    static std::string decryptToString(const std::vector<std::shared_ptr<BigInt>>& encryptedNumbers, const RSA::PrivateKey& privKey);

    // User input validation
    static int getValidatedInt(const std::string& prompt, int min, int max);
    static size_t getValidatedSizeT(const std::string& prompt, size_t min, size_t max);
    static std::string getValidatedString(const std::string& prompt, size_t maxLength = 1000);

    // Formatted key output
    static void printPublicKey(const RSA::PublicKey& key);
    static void printPrivateKey(const RSA::PrivateKey& key, bool showDetails = false);

    // Generates a unique filename
    static std::string generateUniqueFilename(const std::string& baseName, const std::string& extension);
};

#endif // UTILS_HPP
