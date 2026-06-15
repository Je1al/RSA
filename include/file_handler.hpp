#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <string>
#include <vector>
#include <memory>
#include "bigmath.hpp"
#include "rsa.hpp"

// Class for handling file input/output in RSA context
class FileHandler {
public:
    
    static std::vector<uint8_t> readMessageFromFile(const std::string& filename);

    static void writeMessageToFile(const std::string& filename, const std::vector<uint8_t>& message);

    static RSA::PublicKey readPublicKeyFromFile(const std::string& filename);
    static RSA::PrivateKey readPrivateKeyFromFile(const std::string& filename);

    static void writePublicKeyToFile(const std::string& filename, const RSA::PublicKey& key);
    static void writePrivateKeyToFile(const std::string& filename, const RSA::PrivateKey& key);

    static BigInt readEncryptedNumberFromFile(const std::string& filename);
    static void writeEncryptedNumberToFile(const std::string& filename, const BigInt& number);

    static bool fileExists(const std::string& filename);

    static void deleteFile(const std::string& filename);

private:

    // Helper function for reading lines from file
    static std::vector<std::string> readLinesFromFile(const std::string& filename);

    // Helper function for writing lines to file
    static void writeLinesToFile(const std::string& filename, const std::vector<std::string>& lines);
};

#endif // FILE_HANDLER_HPP
