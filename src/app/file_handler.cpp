#include "file_handler.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <cstdio>
#include <algorithm>

using namespace std;

vector<uint8_t> FileHandler::readMessageFromFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    // Get file size
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    // Read data
    vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw runtime_error("Error reading file: " + filename);
    }

    return buffer;
}

void FileHandler::writeMessageToFile(const string& filename, const vector<uint8_t>& message) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Cannot create file: " + filename);
    }

    file.write(reinterpret_cast<const char*>(message.data()), message.size());

    if (!file) {
        throw runtime_error("Error writing to file: " + filename);
    }
}

RSA::PublicKey FileHandler::readPublicKeyFromFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    vector<string> lines;
    string line;

    while (getline(file, line)) {
        // Skip empty lines and comments
        if (!line.empty() && line[0] != '#') {
            lines.push_back(line);
        }
    }

    file.close();

    if (lines.size() < 2) {
        throw runtime_error("Invalid public key file format");
    }

    RSA::PublicKey key;

    try {
        key.n = make_shared<BigInt>(BigInt(lines[0]));  // n (hex)
        key.e = make_shared<BigInt>(BigInt(lines[1]));  // e (hex)

        if (lines.size() > 2) {
            key.bitlen = stoul(lines[2]);  // bitlen (decimal)
        }
        else {
            // Calculate bit length from n
            string n_hex = key.n->toHex();
            key.bitlen = n_hex.length() * 4;  // Each hex character = 4 bits
        }
    }
    catch (const exception& e) {
        throw runtime_error("Error parsing public key: " + string(e.what()));
    }

    return key;
}

RSA::PrivateKey FileHandler::readPrivateKeyFromFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    vector<string> lines;
    string line;

    while (getline(file, line)) {
        // Skip empty lines and comments
        if (!line.empty() && line[0] != '#') {
            lines.push_back(line);
        }
    }

    file.close();

    if (lines.size() < 6) {
        throw runtime_error("Invalid private key file format");
    }

    RSA::PrivateKey key;

    try {
        key.n = make_shared<BigInt>(BigInt(lines[0]));    // n (hex)
        key.d = make_shared<BigInt>(BigInt(lines[1]));    // d (hex)
        key.p = make_shared<BigInt>(BigInt(lines[2]));    // p (hex)
        key.q = make_shared<BigInt>(BigInt(lines[3]));    // q (hex)
        key.dp = make_shared<BigInt>(BigInt(lines[4]));   // dp (hex)
        key.dq = make_shared<BigInt>(BigInt(lines[5]));   // dq (hex)

        if (lines.size() > 6) {
            key.qinv = make_shared<BigInt>(BigInt(lines[6])); // qinv (hex)
        }

        if (lines.size() > 7) {
            key.bitlen = stoul(lines[7]);  // bitlen (decimal)
        }
        else {
            // Calculate bit length from n
            string n_hex = key.n->toHex();
            key.bitlen = n_hex.length() * 4;
        }
    }
    catch (const exception& e) {
        throw runtime_error("Error parsing private key: " + string(e.what()));
    }

    return key;
}

void FileHandler::writePublicKeyToFile(const string& filename, const RSA::PublicKey& key) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot create file: " + filename);
    }

    if (!key.n || !key.e) {
        throw runtime_error("Invalid public key");
    }

    file << key.n->toHex() << endl;
    file << key.e->toHex() << endl;
    file << key.bitlen << endl;

    if (!file) {
        throw runtime_error("Error writing to file: " + filename);
    }

    file.close();
}

void FileHandler::writePrivateKeyToFile(const string& filename, const RSA::PrivateKey& key) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot create file: " + filename);
    }

    if (!key.n || !key.d || !key.p || !key.q) {
        throw runtime_error("Invalid private key");
    }

    file << key.n->toHex() << endl;
    file << key.d->toHex() << endl;
    file << key.p->toHex() << endl;
    file << key.q->toHex() << endl;
    file << key.dp->toHex() << endl;
    file << key.dq->toHex() << endl;
    file << key.qinv->toHex() << endl;
    file << key.bitlen << endl;

    if (!file) {
        throw runtime_error("Error writing to file: " + filename);
    }

    file.close();
}

BigInt FileHandler::readEncryptedNumberFromFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    vector<string> lines;
    string line;

    while (getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            lines.push_back(line);
        }
    }

    file.close();

    if (lines.empty()) {
        throw runtime_error("Empty encrypted file");
    }

    try {
        // First line contains hex representation of the number
        return BigInt(lines[0]);
    }
    catch (const exception& e) {
        throw runtime_error("Error parsing encrypted number: " + string(e.what()));
    }
}

void FileHandler::writeEncryptedNumberToFile(const string& filename, const BigInt& number) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot create file: " + filename);
    }

    file << number.toHex() << endl;

    if (!file) {
        throw runtime_error("Error writing to file: " + filename);
    }

    file.close();
}

bool FileHandler::fileExists(const string& filename) {
    ifstream file(filename);
    return file.good();
}

void FileHandler::deleteFile(const string& filename) {
    if (remove(filename.c_str()) != 0) {
        // Don't throw exception on deletion error
    }
}
