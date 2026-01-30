#include "utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <chrono>
#include <cstring>
#include "bigmath_internal.hpp"

using namespace std;

vector<uint8_t> RSAUtils::stringToBytes(const string& str) {
    vector<uint8_t> bytes;

    // For UTF-8 string
    for (char c : str) {
        bytes.push_back(static_cast<uint8_t>(c));
    }

    return bytes;
}

string RSAUtils::bytesToString(const vector<uint8_t>& bytes) {
    string result;

    // For UTF-8: simply convert bytes to string
    result.reserve(bytes.size());
    for (uint8_t byte : bytes) {
        result.push_back(static_cast<char>(byte));
    }

    return result;
}

shared_ptr<BigInt> RSAUtils::stringToBigInt(const string& str) {
    vector<uint8_t> bytes = stringToBytes(str);
    return RSA::strToNumber(bytes.data(), bytes.size());
}

string RSAUtils::bigIntToString(const BigInt& num) {
    vector<uint8_t> bytes = RSA::numberToStr(num);
    return bytesToString(bytes);
}

vector<vector<uint8_t>> RSAUtils::splitMessage(const vector<uint8_t>& message,
    size_t maxBlockSize) {
    vector<vector<uint8_t>> blocks;

    if (maxBlockSize == 0) {
        throw invalid_argument("Block size cannot be zero");
    }

    for (size_t i = 0; i < message.size(); i += maxBlockSize) {
        size_t blockSize = min(maxBlockSize, message.size() - i);
        vector<uint8_t> block(message.begin() + i, message.begin() + i + blockSize);
        blocks.push_back(block);
    }

    return blocks;
}

vector<uint8_t> RSAUtils::joinBlocks(const vector<vector<uint8_t>>& blocks) {
    vector<uint8_t> result;

    for (const auto& block : blocks) {
        result.insert(result.end(), block.begin(), block.end());
    }

    return result;
}

size_t RSAUtils::calculateMaxBlockSize(const BigInt& n) {
    // Calculate bit length of modulus
    size_t bitLength = exported_count_bits(n);

    // Maximum block size in bytes = floor((bitLength - 1) / 8)
    // Leave 1 bit of margin to guarantee m < n
    size_t maxBytes = (bitLength - 1) / 8;

    return max(static_cast<size_t>(1), maxBytes);
}

vector<shared_ptr<BigInt>> RSAUtils::encryptString(const string& message,
    const RSA::PublicKey& pubKey) {
    vector<shared_ptr<BigInt>> encryptedBlocks;

    // Convert string to bytes
    vector<uint8_t> bytes = stringToBytes(message);

    // Calculate maximum block size
    size_t maxBlockSize = calculateMaxBlockSize(*pubKey.n);

    // Round down to guarantee that the number will be < n
    if (maxBlockSize < 1) maxBlockSize = 1;

    cout << "Debug: Max block size for encryption: " << maxBlockSize << " bytes" << endl;

    // Split message into blocks
    auto blocks = splitMessage(bytes, maxBlockSize);

    // Encrypt each block
    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];

        cout << "Debug: Block " << i << " size: " << block.size() << " bytes" << endl;

        // Convert block to number
        auto blockNumber = RSA::strToNumber(block.data(), block.size());

        if (!blockNumber) {
            throw runtime_error("Failed to convert block to number");
        }

        // Verify that number is less than modulus
        if (blockNumber->cmp(*pubKey.n) >= 0) {
            cout << "Error: Block " << i << " is too large!" << endl;
            cout << "Block number: " << blockNumber->toHex() << endl;
            cout << "Modulus n: " << pubKey.n->toHex() << endl;
            throw runtime_error("Block too large for encryption");
        }

        // Encrypt
        auto encryptedBlock = RSA::encrypt(*blockNumber, pubKey);
        if (!encryptedBlock) {
            throw runtime_error("Failed to encrypt block");
        }

        encryptedBlocks.push_back(encryptedBlock);
    }

    return encryptedBlocks;
}

string RSAUtils::decryptToString(const vector<shared_ptr<BigInt>>& encryptedNumbers,
    const RSA::PrivateKey& privKey) {
    vector<uint8_t> allBytes;

    // Decrypt each block
    for (size_t i = 0; i < encryptedNumbers.size(); ++i) {
        const auto& encryptedNumber = encryptedNumbers[i];

        cout << "Debug: Decrypting block " << i << endl;

        // Decrypt
        auto decryptedNumber = RSA::decrypt(*encryptedNumber, privKey);
        if (!decryptedNumber) {
            throw runtime_error("Failed to decrypt block " + to_string(i));
        }

        // Convert number back to bytes
        auto bytes = RSA::numberToStr(*decryptedNumber);

        cout << "Debug: Block " << i << " decrypted to " << bytes.size() << " bytes" << endl;

        allBytes.insert(allBytes.end(), bytes.begin(), bytes.end());
    }

    // Convert bytes to string
    return bytesToString(allBytes);
}

int RSAUtils::getValidatedInt(const string& prompt, int min, int max) {
    int value;
    while (true) {
        cout << prompt;
        cin >> value;

        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Please enter an integer." << endl;
        }
        else if (value < min || value > max) {
            cout << "Value must be between " << min << " and " << max << "." << endl;
        }
        else {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return value;
        }
    }
}

size_t RSAUtils::getValidatedSizeT(const string& prompt, size_t min, size_t max) {
    size_t value;
    while (true) {
        cout << prompt;
        cin >> value;

        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Please enter a positive integer." << endl;
        }
        else if (value < min || value > max) {
            cout << "Value must be between " << min << " and " << max << "." << endl;
        }
        else {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return value;
        }
    }
}

string RSAUtils::getValidatedString(const string& prompt, size_t maxLength) {
    string input;
    while (true) {
        cout << prompt;
        getline(cin, input);

        if (input.empty()) {
            cout << "Input cannot be empty. Please try again." << endl;
        }
        else if (input.length() > maxLength) {
            cout << "Input too long. Maximum length is " << maxLength << " characters." << endl;
        }
        else {
            return input;
        }
    }
}

void RSAUtils::printPublicKey(const RSA::PublicKey& key) {
    cout << "=== Public Key ===" << endl;
    cout << "Bit length: " << key.bitlen << endl;
    cout << "Modulus (n): " << key.n->toHex() << endl;
    cout << "Exponent (e): " << key.e->toHex() << endl;
    cout << "==================" << endl;
}

void RSAUtils::printPrivateKey(const RSA::PrivateKey& key, bool showDetails) {
    cout << "=== Private Key ===" << endl;
    cout << "Bit length: " << key.bitlen << endl;

    if (showDetails) {
        cout << "Modulus (n): " << key.n->toHex() << endl;
        cout << "Exponent (d): " << key.d->toHex() << endl;
        cout << "Prime p: " << key.p->toHex() << endl;
        cout << "Prime q: " << key.q->toHex() << endl;
        cout << "dp: " << key.dp->toHex() << endl;
        cout << "dq: " << key.dq->toHex() << endl;
        cout << "qinv: " << key.qinv->toHex() << endl;
    }
    else {
        cout << "Modulus (n): " << key.n->toHex().substr(0, 32) << "..." << endl;
        cout << "Exponent (d): " << key.d->toHex().substr(0, 32) << "..." << endl;
    }
    cout << "===================" << endl;
}

string RSAUtils::generateUniqueFilename(const string& baseName,
    const string& extension) {
    auto now = chrono::system_clock::now();
    auto timestamp = chrono::duration_cast<chrono::milliseconds>(
        now.time_since_epoch()).count();

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1000, 9999);

    stringstream ss;
    ss << baseName << "_" << timestamp << "_" << dis(gen) << "." << extension;
    return ss.str();
}
