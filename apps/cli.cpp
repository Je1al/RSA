#include "console_app.hpp"
#include "rsa.hpp"
#include "oaep.hpp"
#include "pss.hpp"
#include "bigmath.hpp"

#include <iostream>
#include <stdexcept>
#include <locale>
#include <string>
#include <vector>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

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
              << "  (no args)   launch the interactive console\n"
              << "  demo        run a non-interactive OAEP + PSS demonstration\n"
              << "  help        show this message\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 1) {
        std::string cmd = argv[1];
        if (cmd == "demo")  return runSecureDemo();
        if (cmd == "help" || cmd == "-h" || cmd == "--help") { printUsage(argv[0]); return 0; }
        std::cerr << "unknown command: " << cmd << "\n";
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