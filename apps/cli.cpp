#include "console_app.hpp"
#include "rsa.hpp"
#include "oaep.hpp"
#include "pss.hpp"
#include "keyio.hpp"
#include "bigmath.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <locale>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

std::string readText(const std::string& path) {
    auto b = readFile(path);
    return std::string(b.begin(), b.end());
}

void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

void writeText(const std::string& path, const std::string& s) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot write " + path);
    f << s;
}

// Subcommands that read/write PEM and raw files, used for OpenSSL interop.
int cmdGenPem(const std::string& pubFile, const std::string& privFile, size_t bits) {
    RSA::PublicKey pub; RSA::PrivateKey priv;
    if (!RSA::generateKeys(pub, priv, bits)) { std::cerr << "keygen failed\n"; return 1; }
    writeText(pubFile, keyio::toPublicPem(pub));
    writeText(privFile, keyio::toPrivatePem(priv));
    return 0;
}

int cmdPssSign(const std::string& privFile, const std::string& msgFile, const std::string& sigFile) {
    auto priv = keyio::privateFromPem(readText(privFile));
    writeFile(sigFile, pss::sign(priv, readFile(msgFile)));
    return 0;
}

int cmdPssVerify(const std::string& pubFile, const std::string& msgFile, const std::string& sigFile) {
    auto pub = keyio::publicFromPem(readText(pubFile));
    bool ok = pss::verify(pub, readFile(msgFile), readFile(sigFile));
    std::cout << (ok ? "VALID" : "INVALID") << "\n";
    return ok ? 0 : 1;
}

int cmdOaepEncrypt(const std::string& pubFile, const std::string& msgFile, const std::string& ctFile) {
    auto pub = keyio::publicFromPem(readText(pubFile));
    writeFile(ctFile, oaep::encrypt(pub, readFile(msgFile)));
    return 0;
}

int cmdOaepDecrypt(const std::string& privFile, const std::string& ctFile, const std::string& outFile) {
    auto priv = keyio::privateFromPem(readText(privFile));
    auto pt = oaep::decrypt(priv, readFile(ctFile));
    if (outFile.empty()) std::cout.write(reinterpret_cast<const char*>(pt.data()),
                                          static_cast<std::streamsize>(pt.size()));
    else writeFile(outFile, pt);
    return 0;
}

std::string toHex(const std::vector<uint8_t>& v, size_t max = 32) {
    static const char* d = "0123456789abcdef";
    std::string s;
    size_t n = std::min(v.size(), max);
    for (size_t i = 0; i < n; ++i) { s += d[v[i] >> 4]; s += d[v[i] & 0xF]; }
    if (v.size() > max) s += "...";
    return s;
}

// Non-interactive end-to-end demonstration of the secure (PKCS#1 v2.2) pipeline.
int runSecureDemo() {
    using clock = std::chrono::steady_clock;
    const size_t bits = 2048;

    std::cout << "RSA toolkit -- secure pipeline demo (RSAES-OAEP + RSASSA-PSS, SHA-256)\n";
    std::cout << "Generating a " << bits << "-bit key with the SP 800-90A CSPRNG...\n";

    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    auto t0 = clock::now();
    if (!RSA::generateKeys(pub, priv, bits)) {
        std::cerr << "key generation failed\n";
        return 1;
    }
    double genMs = std::chrono::duration<double, std::milli>(clock::now() - t0).count();
    std::cout << "  n = " << pub.n->bitLength() << " bits, e = " << pub.e->toHex()
              << "  (" << genMs << " ms)\n\n";

    std::string text = "BMW secure on-board key wrap: K=0x9f86d081...";
    std::vector<uint8_t> msg(text.begin(), text.end());

    std::cout << "OAEP encryption\n";
    auto ct = oaep::encrypt(pub, msg);
    std::cout << "  plaintext : " << text << "\n";
    std::cout << "  ciphertext: " << toHex(ct) << "\n";
    auto pt = oaep::decrypt(priv, ct);
    std::cout << "  decrypted : " << std::string(pt.begin(), pt.end()) << "\n";
    std::cout << "  round-trip: " << (pt == msg ? "OK" : "FAIL") << "\n\n";

    std::cout << "PSS signature\n";
    auto sig = pss::sign(priv, msg);
    std::cout << "  signature : " << toHex(sig) << "\n";
    std::cout << "  verify    : " << (pss::verify(pub, msg, sig) ? "VALID" : "INVALID") << "\n";
    std::vector<uint8_t> tampered = msg; tampered[0] ^= 0x01;
    std::cout << "  tampered  : " << (pss::verify(pub, tampered, sig) ? "VALID" : "INVALID (rejected)")
              << "\n";
    return 0;
}

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [command]\n"
              << "  (no args)                          launch the interactive console\n"
              << "  demo                               OAEP + PSS demonstration\n"
              << "  genpem <pub.pem> <priv.pem>        generate a 2048-bit key to PEM\n"
              << "  pss-sign <priv.pem> <msg> <sig>    RSASSA-PSS sign a file\n"
              << "  pss-verify <pub.pem> <msg> <sig>   RSASSA-PSS verify (exit 0 = valid)\n"
              << "  oaep-encrypt <pub.pem> <in> <out>  RSAES-OAEP encrypt a file\n"
              << "  oaep-decrypt <priv.pem> <in> [out] RSAES-OAEP decrypt a file\n"
              << "  help                               show this message\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 1) {
        std::string cmd = argv[1];
        try {
            if (cmd == "demo") return runSecureDemo();
            if (cmd == "genpem" && argc == 4)       return cmdGenPem(argv[2], argv[3], 2048);
            if (cmd == "pss-sign" && argc == 5)     return cmdPssSign(argv[2], argv[3], argv[4]);
            if (cmd == "pss-verify" && argc == 5)   return cmdPssVerify(argv[2], argv[3], argv[4]);
            if (cmd == "oaep-encrypt" && argc == 5) return cmdOaepEncrypt(argv[2], argv[3], argv[4]);
            if (cmd == "oaep-decrypt" && argc >= 4) return cmdOaepDecrypt(argv[2], argv[3], argc >= 5 ? argv[4] : "");
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            return 1;
        }
        if (cmd == "help" || cmd == "-h" || cmd == "--help") { printUsage(argv[0]); return 0; }
        std::cerr << "unknown or malformed command: " << cmd << "\n";
        printUsage(argv[0]);
        return 2;
    }
    try {
#ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);

        setlocale(LC_ALL, "ru_RU.UTF-8");
#else
        setlocale(LC_ALL, "en_US.UTF-8");
#endif
        
        ConsoleApp app;
        app.showEncodingMenu();
        app.run();

        std::cout << std::endl;
        std::cout << "Program terminated successfully." << std::endl;

        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << std::endl;
        std::cerr << "========================================" << std::endl;
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        std::cerr << "========================================" << std::endl;

        std::cerr << std::endl;
        std::cerr << "The program encountered a critical error and must terminate." << std::endl;
        std::cerr << "Please check the following:" << std::endl;
        std::cerr << "1. Memory availability" << std::endl;
        std::cerr << "2. File permissions" << std::endl;
        std::cerr << "3. Input data validity" << std::endl;

        return 1;

    }
    catch (...) {
        std::cerr << std::endl;
        std::cerr << "========================================" << std::endl;
        std::cerr << "UNKNOWN FATAL ERROR" << std::endl;
        std::cerr << "========================================" << std::endl;

        std::cerr << std::endl;
        std::cerr << "The program encountered an unknown critical error." << std::endl;

        return 2;
    }
}