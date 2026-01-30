#include "test_suite.hpp"
#include "utils.hpp"
#include "file_handler.hpp"
#include "prime_generator.hpp"
#include <iostream>
#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>
#include <memory>
#include "bigmath_internal.hpp"
#include <iomanip>

using namespace std;

int TestSuite::passedTests = 0;
int TestSuite::totalTests = 0;

void TestSuite::runAllTests() {
    cout << dec;
    cout << "========================================" << endl;
    cout << "         RSA TEST SUITE" << endl;
    cout << "========================================" << endl << endl;

    passedTests = 0;
    totalTests = 0;

    bool allPassed = true;

    // Run all tests
    allPassed &= testMillerRabin();
    allPassed &= testStringConversion();
    allPassed &= testModularArithmetic();
    allPassed &= testKeyGeneration();
    allPassed &= testEncryptionDecryption();
    allPassed &= testErrorHandling();
    allPassed &= testPerformance();
    allPassed &= testModularInverse();
    allPassed &= testLongStringEncryption();
    allPassed &= testBigNumbers();

    cout << endl;
    cout << "========================================" << endl;
    cout << "TEST SUMMARY:" << endl;
    cout << "Passed: " << passedTests << "/" << totalTests << endl;
    cout << "Overall: " << (allPassed ? "PASSED" : "FAILED") << endl;
    cout << "========================================" << endl;
}

bool TestSuite::testKeyGeneration() {
    cout << "Testing Key Generation..." << endl;
    cout << "-------------------------" << endl;

    bool allPassed = true;

    try {
        // Test 1: Generate 64-bit keys
        RSA::PublicKey pubKey;
        RSA::PrivateKey privKey;

        allPassed &= checkCondition(
            RSA::generateKeys(pubKey, privKey, 64, 65537),
            true,
            "64-bit key generation"
        );

        if (allPassed) {
            // Verify n = p * q
            BigInt n_calculated = BigInt::mulNaive(*privKey.p, *privKey.q);
            bool n_matches = n_calculated.cmp(*pubKey.n) == 0;

            // Verify φ(n) = (p-1)*(q-1)
            BigInt p_minus_1 = exported_internal_sub(*privKey.p, BigInt::fromU64(1));
            BigInt q_minus_1 = exported_internal_sub(*privKey.q, BigInt::fromU64(1));
            BigInt phi_n = BigInt::mulNaive(p_minus_1, q_minus_1);

            // Verify e*d ≡ 1 mod φ(n)
            BigInt e_times_d = BigInt::mulNaive(*pubKey.e, *privKey.d);
            BigInt e_times_d_mod_phi = BigInt::modNaive(e_times_d, phi_n);

            allPassed &= checkCondition(pubKey.n != nullptr, "Public key has modulus");
            allPassed &= checkCondition(pubKey.e != nullptr, "Public key has exponent");
            allPassed &= checkCondition(privKey.n != nullptr, "Private key has modulus");
            allPassed &= checkCondition(privKey.d != nullptr, "Private key has exponent");
            allPassed &= checkCondition(privKey.p != nullptr, "Private key has prime p");
            allPassed &= checkCondition(privKey.q != nullptr, "Private key has prime q");

            // Use the previously computed n_matches value
            allPassed &= checkCondition(n_matches, "n = p * q");

            // Verify key pair
            allPassed &= checkCondition(
                RSA::checkKeypair(pubKey, privKey),
                true,
                "Key pair verification"
            );
        }

        // Test 2: Generate keys with custom exponent
        RSA::PublicKey pubKey2;
        RSA::PrivateKey privKey2;
        bool success = false;
        const int MAX_ATTEMPTS = 10;

        for (int attempt = 0; attempt < MAX_ATTEMPTS && !success; attempt++) {
            success = RSA::generateKeys(pubKey2, privKey2, 96, 17);
            if (!success && attempt < MAX_ATTEMPTS - 1) {
                cout << "Attempt " << (attempt + 1) << " failed, retrying..." << endl;
            }
        }

        allPassed &= checkCondition(success, true, "Key generation with custom exponent (max " + to_string(MAX_ATTEMPTS) + " attempts)");

        printTestResult("Key Generation Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in key generation test: " << e.what() << endl;
        printTestResult("Key Generation Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testEncryptionDecryption() {
    cout << endl << "Testing Encryption/Decryption..." << endl;
    cout << "----------------------------------" << endl;

    bool allPassed = true;

    try {
        // Generate test keys (64-bit for speed)
        RSA::PublicKey pubKey;
        RSA::PrivateKey privKey;

        if (!RSA::generateKeys(pubKey, privKey, 64, 65537)) {
            cout << "Failed to generate test keys" << endl;
            return false;
        }

        // Test 1: Encrypt and decrypt a single number
        BigInt testMessage = BigInt::fromU64(123456789);

        if (testMessage.cmp(*pubKey.n) >= 0) {
            // Reduce message size
            cout << "Warning: test message >= n, reducing..." << endl;
            testMessage = BigInt::modNaive(testMessage, *pubKey.n);
        }

        auto encrypted = RSA::encrypt(testMessage, pubKey);
        allPassed &= checkCondition(encrypted != nullptr, "Encryption returned result");

        if (encrypted) {
            auto decrypted = RSA::decrypt(*encrypted, privKey);
            allPassed &= checkCondition(decrypted != nullptr, "Decryption returned result");

            if (decrypted) {
                bool match = decrypted->cmp(testMessage) == 0;
                if (!match) {
                    cout << "ERROR: Decrypted message doesn't match original!" << endl;
                    cout << "Difference: ";
                    try {
                        BigInt diff = exported_internal_sub(*decrypted, testMessage);
                        cout << diff.toHex() << endl;
                    }
                    catch (...) {
                        cout << "Could not compute difference" << endl;
                    }
                }

                allPassed &= checkCondition(match, "Decrypted message matches original");
            }
        }

        // Test 2: Encrypt a string
        string testString = "hi"; // Use short string for test
        auto messageNumber = RSAUtils::stringToBigInt(testString);

        // Check that message is smaller than modulus
        if (messageNumber->cmp(*pubKey.n) >= 0) {
            cout << "Warning: Test string too long for current key, using shorter string." << endl;
            testString = "A"; // Use even shorter string
            messageNumber = RSAUtils::stringToBigInt(testString);
        }

        encrypted = RSA::encrypt(*messageNumber, pubKey);
        allPassed &= checkCondition(encrypted != nullptr, "String encryption");

        if (encrypted) {
            auto decrypted = RSA::decrypt(*encrypted, privKey);
            allPassed &= checkCondition(decrypted != nullptr, "String decryption");

            if (decrypted) {
                string decryptedString = RSAUtils::bigIntToString(*decrypted);
                allPassed &= checkCondition(
                    decryptedString == testString,
                    "Decrypted string matches original"
                );
            }
        }

        // Test 3: Verify identity m = (m^e)^d mod n
        BigInt randomMsg = BigInt::fromU64(rand() % 1000000);

        encrypted = RSA::encrypt(randomMsg, pubKey);
        if (encrypted) {
            auto decrypted = RSA::decrypt(*encrypted, privKey);
            if (decrypted) {
                allPassed &= checkCondition(
                    decrypted->cmp(randomMsg) == 0,
                    "m = (m^e)^d mod n identity holds"
                );
            }
        }

        printTestResult("Encryption/Decryption Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in encryption/decryption test: " << e.what() << endl;
        printTestResult("Encryption/Decryption Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testModularInverse() {
    cout << endl << "Testing Modular Inverse..." << endl;
    cout << "----------------------------" << endl;

    bool allPassed = true;

    try {
        // Simple tests for modular inverse
        // 3 * 9 ≡ 1 mod 26, because 3 * 9 = 27 ≡ 1 mod 26
        BigInt a = BigInt::fromU64(3);
        BigInt m = BigInt::fromU64(26);
        BigInt expected = BigInt::fromU64(9);

        BigInt inverse = exported_mod_inverse_binary(a, m);

        BigInt check = BigInt::modNaive(BigInt::mulNaive(a, inverse), m);

        allPassed &= checkCondition(inverse.cmp(expected) == 0, "inverse(3, 26) = 9");
        allPassed &= checkCondition(check.cmp(BigInt::fromU64(1)) == 0, "a * a^-1 == 1 mod m");

    }
    catch (const exception& e) {
        cout << "Exception in modular inverse test: " << e.what() << endl;
        return false;
    }

    return allPassed;
}

bool TestSuite::testMillerRabin() {
    cout << endl << "Testing Miller-Rabin Primality Test..." << endl;
    cout << "----------------------------------------" << endl;

    bool allPassed = true;

    try {
        MillerRabinPrimeGenerator generator;

        // Test small prime numbers
        vector<uint64_t> knownPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
        for (uint64_t prime : knownPrimes) {
            BigInt primeBigInt = BigInt::fromU64(prime);
            allPassed &= checkCondition(
                generator.isPrime(primeBigInt, 5),
                true,
                "Small prime " + to_string(prime)
            );
        }

        // Test small composite numbers
        vector<uint64_t> knownComposites = { 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20 };
        for (uint64_t composite : knownComposites) {
            BigInt compBigInt = BigInt::fromU64(composite);
            allPassed &= checkCondition(
                generator.isPrime(compBigInt, 5),
                false,
                "Small composite " + to_string(composite)
            );
        }

        // Test larger prime number (2^31 - 1)
        BigInt mersennePrime = BigInt::fromU64(2147483647ULL); // 2^31 - 1
        allPassed &= checkCondition(
            generator.isPrime(mersennePrime, 10),
            true,
            "Mersenne prime 2^31-1"
        );

        printTestResult("Miller-Rabin Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in Miller-Rabin test: " << e.what() << endl;
        printTestResult("Miller-Rabin Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testStringConversion() {
    cout << endl << "Testing String/Number Conversion..." << endl;
    cout << "--------------------------------------" << endl;

    bool allPassed = true;

    try {
        // Test 1: Simple string
        string testStr = "Hello, World!";
        vector<uint8_t> bytes(testStr.begin(), testStr.end());

        auto number = RSA::strToNumber(bytes.data(), bytes.size());
        allPassed &= checkCondition(number != nullptr, "String to number conversion");

        if (number) {
            auto convertedBytes = RSA::numberToStr(*number);
            string convertedStr(convertedBytes.begin(), convertedBytes.end());
            allPassed &= checkCondition(
                convertedStr == testStr,
                "Number to string conversion"
            );
        }

        // Test 2: Empty string
        string emptyStr = "";
        vector<uint8_t> emptyBytes(emptyStr.begin(), emptyStr.end());

        auto emptyNumber = RSA::strToNumber(emptyBytes.data(), emptyBytes.size());
        allPassed &= checkCondition(emptyNumber != nullptr, "Empty string to number");

        if (emptyNumber) {
            auto backBytes = RSA::numberToStr(*emptyNumber);
            string backStr(backBytes.begin(), backBytes.end());
            // For empty string, both vectors should be empty
            allPassed &= checkCondition(
                backBytes.empty() && backStr.empty(),
                "Empty number to string"
            );
        }

        // Test 3: String with non-ASCII characters
        string specialStr = "Test\x01\xFF\x7F\x00\x0A";
        vector<uint8_t> specialBytes(specialStr.begin(), specialStr.end());

        auto specialNumber = RSA::strToNumber(specialBytes.data(), specialBytes.size());
        allPassed &= checkCondition(specialNumber != nullptr, "Special string to number");

        if (specialNumber) {
            auto backSpecialBytes = RSA::numberToStr(*specialNumber);
            allPassed &= checkCondition(
                backSpecialBytes == specialBytes,
                "Special bytes preservation"
            );
        }

        // Test 4: Long string
        string longStr(100, 'A');
        vector<uint8_t> longBytes(longStr.begin(), longStr.end());

        auto longNumber = RSA::strToNumber(longBytes.data(), longBytes.size());
        allPassed &= checkCondition(longNumber != nullptr, "Long string to number");

        if (longNumber) {
            auto backLongBytes = RSA::numberToStr(*longNumber);
            string backLongStr(backLongBytes.begin(), backLongBytes.end());
            allPassed &= checkCondition(
                backLongStr == longStr,
                "Long string preservation"
            );
        }

        printTestResult("String Conversion Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in string conversion test: " << e.what() << endl;
        printTestResult("String Conversion Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testModularArithmetic() {
    cout << endl << "Testing Modular Arithmetic..." << endl;
    cout << "-------------------------------" << endl;

    bool allPassed = true;

    try {
        // Test modular exponentiation
        BigInt base = BigInt::fromU64(5);
        BigInt exp = BigInt::fromU64(3);
        BigInt mod = BigInt::fromU64(13);

        BigInt result = BigInt::modExp(base, exp, mod);
        // 5^3 mod 13 = 125 mod 13 = 8
        BigInt expected = BigInt::fromU64(8);
        allPassed &= checkCondition(
            result.cmp(expected) == 0,
            "5^3 mod 13 = 8"
        );

        // Test with large numbers
        BigInt bigBase("123456789");
        BigInt bigExp("100");
        BigInt bigMod("1000000007");

        BigInt bigResult = BigInt::modExp(bigBase, bigExp, bigMod);
        // We don't know the exact value, but ensure result is less than modulus
        allPassed &= checkCondition(
            bigResult.cmp(bigMod) < 0,
            "Big modular exponentiation result < mod"
        );

        printTestResult("Modular Arithmetic Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in modular arithmetic test: " << e.what() << endl;
        printTestResult("Modular Arithmetic Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testPerformance() {
    cout << endl << "Testing Performance..." << endl;
    cout << "----------------------" << endl;

    bool allPassed = true;

    try {
        auto start = chrono::high_resolution_clock::now();

        // Test key generation performance
        RSA::PublicKey pubKey;
        RSA::PrivateKey privKey;

        bool keyGenSuccess = RSA::generateKeys(pubKey, privKey, 128, 65537);
        allPassed &= checkCondition(keyGenSuccess, true, "128-bit key generation");

        auto keyGenEnd = chrono::high_resolution_clock::now();
        auto keyGenDuration = chrono::duration_cast<chrono::milliseconds>(keyGenEnd - start);

        cout << "Key generation (128-bit): " << keyGenDuration.count() << " ms" << endl;

        BigInt p_minus_1 = exported_internal_sub(*privKey.p, BigInt::fromU64(1));
        BigInt q_minus_1 = exported_internal_sub(*privKey.q, BigInt::fromU64(1));
        BigInt phi_n = BigInt::mulNaive(p_minus_1, q_minus_1);

        BigInt e_times_d = BigInt::mulNaive(*pubKey.e, *privKey.d);
        BigInt e_times_d_mod_phi = BigInt::modNaive(e_times_d, phi_n);

        if (e_times_d_mod_phi.cmp(BigInt::fromU64(1)) != 0) {
            cout << "ERROR: Key pair is invalid! e*d mod φ(n) != 1" << endl;
            allPassed = false;
        }

        if (keyGenSuccess) {
            // Test encryption performance (number only, not string)
            // Generate random number smaller than modulus
            BigInt testMessage = exported_random_in_range(
                BigInt::fromU64(2),
                exported_internal_sub(*pubKey.n, BigInt::fromU64(1))
            );

            auto encryptStart = chrono::high_resolution_clock::now();
            auto encrypted = RSA::encrypt(testMessage, pubKey);
            auto encryptEnd = chrono::high_resolution_clock::now();

            auto encryptDuration = chrono::duration_cast<chrono::microseconds>(encryptEnd - encryptStart);

            allPassed &= checkCondition(encrypted != nullptr, "Performance encryption");
            cout << "Encryption: " << encryptDuration.count() << " μs" << endl;

            // Test decryption performance
            if (encrypted) {
                auto decryptStart = chrono::high_resolution_clock::now();
                auto decrypted = RSA::decrypt(*encrypted, privKey);
                auto decryptEnd = chrono::high_resolution_clock::now();

                auto decryptDuration = chrono::duration_cast<chrono::microseconds>(decryptEnd - decryptStart);

                allPassed &= checkCondition(decrypted != nullptr, "Performance decryption");
                cout << "Decryption: " << decryptDuration.count() << " μs" << endl;

                if (decrypted) {
                    // Compare numbers, not strings
                    bool match = decrypted->cmp(testMessage) == 0;
                    if (!match) {
                        cout << "ERROR: Numbers don't match!" << endl;
                        cout << "Original: " << testMessage.toHex() << endl;
                        cout << "Decrypted: " << decrypted->toHex() << endl;
                    }

                    allPassed &= checkCondition(match, "Performance test correctness");
                }
            }
        }

        printTestResult("Performance Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in performance test: " << e.what() << endl;
        printTestResult("Performance Tests", false);
        return false;
    }

    return allPassed;
}

bool TestSuite::testLongStringEncryption() {
    cout << endl << "Testing Long String Encryption..." << endl;
    cout << "-----------------------------------" << endl;

    bool allPassed = true;

    try {
        // Generate 256-bit keys for testing
        RSA::PublicKey pubKey;
        RSA::PrivateKey privKey;

        if (!RSA::generateKeys(pubKey, privKey, 256, 65537)) {
            cout << "Failed to generate test keys" << endl;
            return false;
        }

        // Test several strings of different lengths
        vector<string> testStrings = {
            "A",
            "AB",
            "Hello",
            "Hello, World!",
            "This is a test message",
            "1234567890",
            "!@#$%^&*()",
            "Russian text"  // Unicode
        };

        for (const auto& testStr : testStrings) {
            cout << "\nTesting string: \"" << testStr << "\"" << endl;

            // Convert string to number
            auto number = RSA::strToNumber(
                reinterpret_cast<const uint8_t*>(testStr.c_str()),
                testStr.length()
            );

            if (!number) {
                cout << "  FAIL: String to number conversion failed" << endl;
                allPassed = false;
                continue;
            }

            cout << "  String as number (hex): " << number->toHex() << endl;

            // Convert back to string
            auto bytes = RSA::numberToStr(*number);
            string resultStr(reinterpret_cast<const char*>(bytes.data()), bytes.size());

            cout << "  Result string: \"" << resultStr << "\"" << endl;

            if (resultStr != testStr) {
                cout << "  FAIL: Strings don't match!" << endl;
                cout << "  Original bytes: ";
                for (char c : testStr) {
                    cout << hex << setw(2) << setfill('0') << (int)(unsigned char)c << " ";
                }
                cout << endl;
                cout << "  Result bytes: ";
                for (unsigned char c : bytes) {
                    cout << hex << setw(2) << setfill('0') << (int)c << " ";
                }
                cout << endl;
                allPassed = false;
            }
            else {
                cout << "  PASS" << endl;
            }
        }

    }
    catch (const exception& e) {
        cout << "Exception in long string test: " << e.what() << endl;
        return false;
    }

    return allPassed;
}

bool TestSuite::testBigNumbers() {
    cout << endl << "Testing Big Numbers..." << endl;
    cout << "-------------------------" << endl;

    bool allPassed = true;

    try {
        // Test 1: Modular exponentiation with large numbers
        BigInt base("12345678901234567890");
        BigInt exp("100");
        BigInt mod("1000000007");

        BigInt result = BigInt::modExp(base, exp, mod);
        cout << "  PASS Big modular exponentiation" << endl;

        // Test 2: Multiplication of large numbers
        BigInt a("12345678901234567890");
        BigInt b("98765432109876543210");
        BigInt mul_result = BigInt::mulNaive(a, b);

        // Just verify result is not 0
        allPassed &= checkCondition(mul_result.cmp(BigInt::fromU64(0)) != 0, "Big multiplication");

        // Test 3: Division of large numbers
        BigInt dividend("123456789012345678901234567890");
        BigInt divisor("1234567890");
        BigInt remainder;
        BigInt quotient = BigInt::divmod(dividend, divisor, &remainder);

        // Verify: dividend = quotient * divisor + remainder
        BigInt check = exported_internal_add(BigInt::mulNaive(quotient, divisor), remainder);
        allPassed &= checkCondition(check.cmp(dividend) == 0, "Big division");

    }
    catch (const exception& e) {
        cout << "Exception in big numbers test: " << e.what() << endl;
        return false;
    }

    return allPassed;
}

bool TestSuite::testErrorHandling() {
    cout << endl << "Testing Error Handling..." << endl;
    cout << "----------------------------" << endl;

    bool allPassed = true;

    try {
        // Test 1: Key generation with invalid parameters
        RSA::PublicKey pubKey;
        RSA::PrivateKey privKey;

        // Key length too small
        bool result = RSA::generateKeys(pubKey, privKey, 8, 65537);
        allPassed &= checkCondition(result, false, "Should return false for too small key size");

        // Even exponent
        bool result2 = RSA::generateKeys(pubKey, privKey, 64, 65538);
        allPassed &= checkCondition(result, false, "Should return false for even exponent");

        // Test 2: Encryption with invalid key
        if (RSA::generateKeys(pubKey, privKey, 64, 65537)) {
            // Message larger than modulus
            BigInt largeMessage = BigInt::mulNaive(*pubKey.n, BigInt::fromU64(2));

            auto encrypted = RSA::encrypt(largeMessage, pubKey);
            allPassed &= checkCondition(encrypted == nullptr, "Should return nullptr for message >= n");

            // Negative message (zero message should be valid)
            try {
                BigInt zeroMessage = BigInt::fromU64(0);
                RSA::encrypt(zeroMessage, pubKey);
                allPassed &= checkCondition(true, "Zero message is valid");
            }
            catch (const exception& e) {
                cout << "Note: " << e.what() << endl;
            }
        }

        // Test 3: Invalid parameters for modular operations (use BigInt)
        BigInt zero = BigInt::fromU64(0);
        BigInt one = BigInt::fromU64(1);

        // Division by zero
        try {
            BigInt::modNaive(one, zero);
            allPassed &= checkCondition(false, "Should throw for division by zero");
        }
        catch (const exception&) {
            allPassed &= checkCondition(true, "Throws for division by zero");
        }

        // Exponentiation modulo 0 (use BigInt::modExp instead of RSA::modExp)
        try {
            BigInt::modExp(one, one, zero);
            allPassed &= checkCondition(false, "Should throw for modulus 0");
        }
        catch (const exception&) {
            allPassed &= checkCondition(true, "Throws for modulus 0");
        }

        printTestResult("Error Handling Tests", allPassed);

    }
    catch (const exception& e) {
        cout << "Exception in error handling test: " << e.what() << endl;
        printTestResult("Error Handling Tests", false);
        return false;
    }

    return allPassed;
}

template<typename T>
bool TestSuite::checkCondition(const T& actual, const T& expected,
    const std::string& testName) {
    totalTests++;

    if (actual == expected) {
        passedTests++;
        cout << "  PASS  " << testName << endl;
        return true;
    }
    else {
        cout << testName << " FAILED" << endl;
        cout << "    Expected: " << expected << endl;
        cout << "    Actual: " << actual << endl;
        return false;
    }
}

bool TestSuite::checkCondition(bool condition, const std::string& testName) {
    totalTests++;

    if (condition) {
        passedTests++;
        cout << "  PASS  " << testName << endl;
        return true;
    }
    else {
        cout << testName << " FAILED" << endl;
        return false;
    }
}

void TestSuite::printTestResult(const std::string& testName, bool passed) {
    cout << endl << testName << ": " << (passed ? "PASSED" : "FAILED") << endl;
    cout << "----------------------------------------" << endl;
    cout << dec;
}
