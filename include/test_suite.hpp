#ifndef TEST_SUITE_HPP
#define TEST_SUITE_HPP

#include "rsa.hpp"
#include "bigmath.hpp"
#include <string>
#include <vector>
#include <memory>

// Test suite for verifying the correctness of RSA implementation
class TestSuite {
public:
    
    static void runAllTests();

    static bool testKeyGeneration();
    static bool testEncryptionDecryption();
    static bool testMillerRabin();
    static bool testStringConversion();
    static bool testModularArithmetic();
    static bool testPerformance();
    static bool testErrorHandling();
    static bool testModularInverse();
    static bool testLongStringEncryption();
    static bool testBigNumbers();

private:

    // Check condition with expected and actual values
    template<typename T>
    static bool checkCondition(const T& actual, const T& expected, const std::string& testName);

    // Check condition (without expected value)
    static bool checkCondition(bool condition, const std::string& testName);

    static void printTestResult(const std::string& testName, bool passed);

    static int passedTests;
    static int totalTests;
};

#endif // TEST_SUITE_HPP
