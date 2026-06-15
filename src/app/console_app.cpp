#include "console_app.hpp"
#include "test_suite.hpp"
#include <iostream>
#include <iomanip>
#include <limits>
#include <stdexcept>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace std;

ConsoleApp::ConsoleApp() : hasKeys(false), showDetailedOutput(true) {
    // Initialization
}

ConsoleApp::~ConsoleApp() = default;

void ConsoleApp::run() {
    int choice;

    do {
        clearScreen();
        showMainMenu();

        cout << "\nEnter your choice (1-7): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);
            handleMainMenuChoice(choice);

        }
        catch (const exception& e) {
            cout << "\nInvalid input! Please enter a number between 1 and 7." << endl;
            waitForEnter();
        }

    } while (choice != 7);
}

void ConsoleApp::showMainMenu() {
    cout << "\nMAIN MENU\n";
    printSeparator();

    cout << "1. Key Management" << endl;
    cout << "2. Encryption" << endl;
    cout << "3. Decryption" << endl;
    cout << "4. File Operations" << endl;
    cout << "5. Testing" << endl;
    cout << "6. Settings" << endl;
    cout << "7. Exit" << endl;

    printSeparator();

    if (hasKeys) {
        cout << "Keys are loaded ("
            << (currentPublicKey ? currentPublicKey->bitlen : 0)
            << " bits)" << endl;
    }
    else {
        cout << "No keys loaded" << endl;
    }
}

void ConsoleApp::handleMainMenuChoice(int choice) {
    switch (choice) {
    case 1:
        showKeyMenu();
        break;
    case 2:
        if (hasKeys) {
            showEncryptionMenu();
        }
        else {
            cout << "\nError: No keys loaded. Please generate or load keys first." << endl;
            waitForEnter();
        }
        break;
    case 3:
        if (hasKeys) {
            showDecryptionMenu();
        }
        else {
            cout << "\nError: No keys loaded. Please generate or load keys first." << endl;
            waitForEnter();
        }
        break;
    case 4:
        showFileMenu();
        break;
    case 5:
        showTestMenu();
        break;
    case 6:
        showDetailedOutput = !showDetailedOutput;
        cout << "\nDetailed output: " << (showDetailedOutput ? "ON" : "OFF") << endl;
        waitForEnter();
        break;
    case 7:
        cout << "\nEnd of the program." << endl;
        break;
    default:
        cout << "\nInvalid choice! Please try again." << endl;
        waitForEnter();
    }
}

void ConsoleApp::showKeyMenu() {
    int choice;

    do {
        clearScreen();
        printHeader("KEY MANAGEMENT");

        cout << "\n1. Generate new keys" << endl;
        cout << "2. Load keys from file" << endl;
        cout << "3. Save keys to file" << endl;
        cout << "4. Show current keys" << endl;
        cout << "5. Clear keys" << endl;
        cout << "6. Back to main menu" << endl;

        cout << "\nEnter your choice (1-6): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);

            switch (choice) {
            case 1:
                generateKeys();
                break;
            case 2:
                loadKeysFromFile();
                break;
            case 3:
                saveKeysToFile();
                break;
            case 4:
                showCurrentKeys();
                break;
            case 5:
                currentPublicKey.reset();
                currentPrivateKey.reset();
                hasKeys = false;
                cout << "\nKeys cleared." << endl;
                waitForEnter();
                break;
            case 6:
                return;
            default:
                cout << "\nInvalid choice!" << endl;
                waitForEnter();
            }

        }
        catch (const exception& e) {
            cout << "\nError: " << e.what() << endl;
            waitForEnter();
        }

    } while (true);
}

void ConsoleApp::showEncryptionMenu() {
    int choice;

    do {
        clearScreen();
        printHeader("ENCRYPTION");

        cout << "\n1. Encrypt manual input" << endl;
        cout << "2. Encrypt from file" << endl;
        cout << "3. Back to main menu" << endl;

        cout << "\nEnter your choice (1-3): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);

            switch (choice) {
            case 1:
                encryptManual();
                break;
            case 2:
                encryptFromFile();
                break;
            case 3:
                return;
            default:
                cout << "\nInvalid choice!" << endl;
                waitForEnter();
            }

        }
        catch (const exception& e) {
            cout << "\nError: " << e.what() << endl;
            waitForEnter();
        }

    } while (true);
}

void ConsoleApp::showDecryptionMenu() {
    int choice;

    do {
        clearScreen();
        printHeader("DECRYPTION");

        cout << "\n1. Decrypt manual input" << endl;
        cout << "2. Decrypt from file" << endl;
        cout << "3. Back to main menu" << endl;

        cout << "\nEnter your choice (1-3): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);

            switch (choice) {
            case 1:
                decryptManual();
                break;
            case 2:
                decryptFromFile();
                break;
            case 3:
                return;
            default:
                cout << "\nInvalid choice!" << endl;
                waitForEnter();
            }

        }
        catch (const exception& e) {
            cout << "\nError: " << e.what() << endl;
            waitForEnter();
        }

    } while (true);
}

void ConsoleApp::showFileMenu() {
    int choice;

    do {
        clearScreen();
        printHeader("FILE OPERATIONS");

        cout << "\n1. Encrypt file" << endl;
        cout << "2. Decrypt file" << endl;
        cout << "3. Test file operations" << endl;
        cout << "4. Back to main menu" << endl;

        cout << "\nEnter your choice (1-4): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);

            switch (choice) {
            case 1:
                encryptFromFile();
                break;
            case 2:
                decryptFromFile();
                break;
            case 3:
                // Test file operations
                cout << "\nFile operations test:" << endl;
                cout << "Testing file I/O..." << endl;

                try {
                    // Create test file
                    string testFilename = "test_file.txt";
                    ofstream testFile(testFilename);
                    testFile << "This is a test file for RSA encryption." << endl;
                    testFile.close();

                    cout << "Test file created: " << testFilename << endl;

                    // Read test file
                    auto content = FileHandler::readMessageFromFile(testFilename);
                    cout << "File read successfully (" << content.size() << " bytes)" << endl;

                    // Delete test file
                    FileHandler::deleteFile(testFilename);
                    cout << "Test file deleted" << endl;

                    cout << "All file operations test passed!" << endl;
                }
                catch (const exception& e) {
                    cout << "File operations test failed: " << e.what() << endl;
                }

                waitForEnter();
                break;
            case 4:
                return;
            default:
                cout << "\nInvalid choice!" << endl;
                waitForEnter();
            }

        }
        catch (const exception& e) {
            cout << "\nError: " << e.what() << endl;
            waitForEnter();
        }

    } while (true);
}

void ConsoleApp::showTestMenu() {
    int choice;

    do {
        clearScreen();
        printHeader("TESTING");

        cout << "\n1. Run all tests" << endl;
        cout << "2. Test key generation" << endl;
        cout << "3. Test encryption/decryption" << endl;
        cout << "4. Test Miller-Rabin" << endl;
        cout << "5. Test string conversion" << endl;
        cout << "6. Test modular arithmetic" << endl;
        cout << "7. Test error handling" << endl;
        cout << "8. Test performance" << endl;
        cout << "9. Test modular inverse" << endl;
        cout << "10. Test long string encryption" << endl;
        cout << "11. Test big numbers" << endl;
        cout << "12. Back to main menu" << endl;

        cout << "\nEnter your choice (1-12): ";

        try {
            string input;
            getline(cin, input);

            if (input.empty()) {
                continue;
            }

            choice = stoi(input);

            switch (choice) {
            case 1:
                runAllTests();
                break;
            case 2:
                TestSuite::testKeyGeneration();
                waitForEnter();
                break;
            case 3:
                TestSuite::testEncryptionDecryption();
                waitForEnter();
                break;
            case 4:
                TestSuite::testMillerRabin();
                waitForEnter();
                break;
            case 5:
                TestSuite::testStringConversion();
                waitForEnter();
                break;
            case 6:
                TestSuite::testModularArithmetic();
                waitForEnter();
                break;
            case 7:
                TestSuite::testErrorHandling();
                waitForEnter();
                break;
            case 8:
                TestSuite::testPerformance();
                waitForEnter();
                break;
            case 9:
                TestSuite::testModularInverse();
                waitForEnter();
                break;
            case 10:
                TestSuite::testLongStringEncryption();
                waitForEnter();
                break;
            case 11:
                TestSuite::testBigNumbers();
                waitForEnter();
                break;
            case 12:
                return;
            default:
                cout << "\nInvalid choice!" << endl;
                waitForEnter();
            }

        }
        catch (const exception& e) {
            cout << "\nError: " << e.what() << endl;
            waitForEnter();
        }

    } while (true);
}

void ConsoleApp::generateKeys() {
    clearScreen();
    printHeader("GENERATE NEW KEYS");

    try {
        // Key size selection
        cout << "\nSelect key size:" << endl;
        cout << "1. 64 bits (for testing only)" << endl;
        cout << "2. 128 bits (fast)" << endl;
        cout << "3. 256 bits (standard)" << endl;
        cout << "4. 512 bits (secure)" << endl;
        cout << "5. Custom size" << endl;

        cout << "\nEnter your choice (1-5): ";

        string input;
        getline(cin, input);

        if (input.empty()) {
            cout << "\nOperation cancelled." << endl;
            waitForEnter();
            return;
        }

        int sizeChoice = stoi(input);
        size_t keySize;

        switch (sizeChoice) {
        case 1:
            keySize = 64;
            break;
        case 2:
            keySize = 128;
            break;
        case 3:
            keySize = 256;
            break;
        case 4:
            keySize = 512;
            break;
        case 5:
            cout << "\nEnter custom key size (in bits, 16-1024): ";
            getline(cin, input);
            keySize = stoul(input);

            if (keySize < 16 || keySize > 1024) {
                cout << "\nError: Key size must be between 16 and 1024 bits." << endl;
                waitForEnter();
                return;
            }
            break;
        default:
            cout << "\nInvalid choice!" << endl;
            waitForEnter();
            return;
        }

        // Public exponent selection
        cout << "\nSelect public exponent:" << endl;
        cout << "1. Use default (65537)" << endl;
        cout << "2. Enter custom exponent" << endl;

        cout << "\nEnter your choice (1-2): ";
        getline(cin, input);

        uint32_t exponent;
        if (input == "2") {
            cout << "\nEnter custom exponent (must be odd): ";
            getline(cin, input);
            exponent = stoul(input);

            if (exponent % 2 == 0) {
                cout << "\nError: Exponent must be odd." << endl;
                waitForEnter();
                return;
            }
        }
        else {
            exponent = RSA::DEFAULT_E;
        }

        // Key generation
        cout << "\nGenerating RSA keys... This may take a while." << endl;

        currentPublicKey = make_unique<RSA::PublicKey>();
        currentPrivateKey = make_unique<RSA::PrivateKey>();

        bool success = RSA::generateKeys(*currentPublicKey, *currentPrivateKey,
            keySize, exponent);

        if (success) {
            hasKeys = true;
            cout << "\nKeys generated successfully!" << endl;

            if (showDetailedOutput) {
                RSAUtils::printPublicKey(*currentPublicKey);
                cout << endl;
            }

            // Prompt to save keys
            cout << "\nDo you want to save keys to files? (y/n): ";
            getline(cin, input);

            if (input == "y" || input == "Y") {
                saveKeysToFile();
            }

        }
        else {
            cout << "\nKey generation failed!" << endl;
            currentPublicKey.reset();
            currentPrivateKey.reset();
            hasKeys = false;
        }

    }
    catch (const exception& e) {
        cout << "\nError during key generation: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::loadKeysFromFile() {
    clearScreen();
    printHeader("LOAD KEYS FROM FILE");

    try {
        string pubFilename, privFilename;

        cout << "\nEnter filename for public key: ";
        getline(cin, pubFilename);

        cout << "Enter filename for private key: ";
        getline(cin, privFilename);

        if (pubFilename.empty() || privFilename.empty()) {
            cout << "\nError: Filenames cannot be empty." << endl;
            waitForEnter();
            return;
        }

        cout << "\nLoading keys..." << endl;

        RSA::PublicKey pubKey = FileHandler::readPublicKeyFromFile(pubFilename);
        RSA::PrivateKey privKey = FileHandler::readPrivateKeyFromFile(privFilename);

        // Verify key pair
        if (RSA::checkKeypair(pubKey, privKey)) {
            currentPublicKey = make_unique<RSA::PublicKey>(move(pubKey));
            currentPrivateKey = make_unique<RSA::PrivateKey>(move(privKey));
            hasKeys = true;

            cout << "\nKeys loaded successfully!" << endl;

            if (showDetailedOutput) {
                RSAUtils::printPublicKey(*currentPublicKey);
            }

        }
        else {
            cout << "\nKey pair verification failed! The keys may not match." << endl;
        }

    }
    catch (const exception& e) {
        cout << "\nError loading keys: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::saveKeysToFile() {
    if (!hasKeys) {
        cout << "\nError: No keys to save." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("SAVE KEYS TO FILE");

    try {
        string pubFilename, privFilename;

        cout << "\nEnter filename for public key: ";
        getline(cin, pubFilename);

        cout << "Enter filename for private key: ";
        getline(cin, privFilename);

        if (pubFilename.empty() || privFilename.empty()) {
            cout << "\nError: Filenames cannot be empty." << endl;
            waitForEnter();
            return;
        }

        // Check if files exist
        bool overwrite = false;
        if (FileHandler::fileExists(pubFilename) || FileHandler::fileExists(privFilename)) {
            cout << "\nWarning: One or both files already exist." << endl;
            cout << "Overwrite? (y/n): ";

            string input;
            getline(cin, input);

            if (input != "y" && input != "Y") {
                cout << "\nOperation cancelled." << endl;
                waitForEnter();
                return;
            }
            overwrite = true;
        }

        cout << "\nSaving keys..." << endl;

        FileHandler::writePublicKeyToFile(pubFilename, *currentPublicKey);
        FileHandler::writePrivateKeyToFile(privFilename, *currentPrivateKey);

        cout << "\nKeys saved successfully!" << endl;
        cout << "Public key: " << pubFilename << endl;
        cout << "Private key: " << privFilename << endl;

    }
    catch (const exception& e) {
        cout << "\nError saving keys: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::showCurrentKeys() {
    if (!hasKeys) {
        cout << "\nNo keys loaded." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("CURRENT KEYS");

    RSAUtils::printPublicKey(*currentPublicKey);
    cout << endl;
    RSAUtils::printPrivateKey(*currentPrivateKey, showDetailedOutput);

    waitForEnter();
}

void ConsoleApp::encryptManual() {
    if (!hasKeys) {
        cout << "\nError: No keys loaded." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("MANUAL ENCRYPTION");

    try {
        cout << "\nEnter message to encrypt:" << endl;
        cout << "> ";

        string message;
        getline(cin, message);

        if (message.empty()) {
            cout << "\nError: Message cannot be empty." << endl;
            waitForEnter();
            return;
        }

        cout << "\nEncrypting..." << endl;

        // Convert string to number and encrypt
        auto messageNumber = RSAUtils::stringToBigInt(message);

        // Check if message is smaller than modulus
        if (messageNumber->cmp(*currentPublicKey->n) >= 0) {
            cout << "\nError: Message is too long for the current key size." << endl;
            cout << "Message (as number): " << messageNumber->toHex() << endl;
            cout << "Modulus n: " << currentPublicKey->n->toHex() << endl;
            waitForEnter();
            return;
        }

        auto encrypted = RSA::encrypt(*messageNumber, *currentPublicKey);

        if (!encrypted) {
            cout << "\nEncryption failed!" << endl;
            waitForEnter();
            return;
        }

        cout << "\nEncryption successful!" << endl;

        if (showDetailedOutput) {
            cout << "\nOriginal message: " << message << endl;
            cout << "As number: " << messageNumber->toHex() << endl;
            cout << "\nEncrypted result (hex): " << endl;
            cout << encrypted->toHex() << endl;
        }
        else {
            cout << "\nEncrypted (hex): " << encrypted->toHex() << endl;
        }

        // Prompt to save result
        cout << "\nSave encrypted result to file? (y/n): ";
        string input;
        getline(cin, input);

        if (input == "y" || input == "Y") {
            cout << "\nEnter filename: ";
            getline(cin, input);

            if (!input.empty()) {
                FileHandler::writeEncryptedNumberToFile(input, *encrypted);
                cout << "Saved to " << input << endl;
            }
        }

    }
    catch (const exception& e) {
        cout << "\nError during encryption: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::decryptManual() {
    if (!hasKeys) {
        cout << "\nError: No keys loaded." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("MANUAL DECRYPTION");

    try {
        cout << "\nEnter encrypted number (hex):" << endl;
        cout << "> ";

        string hexInput;
        getline(cin, hexInput);

        if (hexInput.empty()) {
            cout << "\nError: Input cannot be empty." << endl;
            waitForEnter();
            return;
        }

        // Convert hex string to BigInt
        BigInt encryptedNumber(hexInput);

        cout << "\nDecrypting..." << endl;

        auto decrypted = RSA::decrypt(encryptedNumber, *currentPrivateKey);

        if (!decrypted) {
            cout << "\nDecryption failed!" << endl;
            waitForEnter();
            return;
        }

        cout << "\nDecryption successful!" << endl;

        // Convert number back to string
        string decryptedMessage = RSAUtils::bigIntToString(*decrypted);

        if (showDetailedOutput) {
            cout << "\nEncrypted input (hex): " << hexInput << endl;
            cout << "Decrypted number (hex): " << decrypted->toHex() << endl;
            cout << "\nDecrypted message: " << endl;
            cout << "==================" << endl;
            cout << decryptedMessage << endl;
            cout << "==================" << endl;
        }
        else {
            cout << "\nDecrypted message: " << decryptedMessage << endl;
        }

    }
    catch (const exception& e) {
        cout << "\nError during decryption: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::encryptFromFile() {
    if (!hasKeys) {
        cout << "\nError: No keys loaded." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("ENCRYPT FROM FILE");

    try {
        string inputFile, outputFile;

        cout << "\nEnter input filename: ";
        getline(cin, inputFile);

        cout << "Enter output filename: ";
        getline(cin, outputFile);

        if (inputFile.empty() || outputFile.empty()) {
            cout << "\nError: Filenames cannot be empty." << endl;
            waitForEnter();
            return;
        }

        // Check if input file exists
        if (!FileHandler::fileExists(inputFile)) {
            cout << "\nError: Input file does not exist." << endl;
            waitForEnter();
            return;
        }

        // Check if output file exists
        if (FileHandler::fileExists(outputFile)) {
            cout << "\nWarning: Output file already exists." << endl;
            cout << "Overwrite? (y/n): ";

            string input;
            getline(cin, input);

            if (input != "y" && input != "Y") {
                cout << "\nOperation cancelled." << endl;
                waitForEnter();
                return;
            }
        }

        cout << "\nReading file..." << endl;

        // Read file
        auto fileContent = FileHandler::readMessageFromFile(inputFile);
        string message(fileContent.begin(), fileContent.end());

        cout << "File size: " << fileContent.size() << " bytes" << endl;

        // Check message size
        size_t maxBlockSize = RSAUtils::calculateMaxBlockSize(*currentPublicKey->n);
        if (message.size() > maxBlockSize * 100) { // Limit for very large files
            cout << "\nWarning: File is very large. This may take a while." << endl;
            cout << "Continue? (y/n): ";

            string input;
            getline(cin, input);

            if (input != "y" && input != "Y") {
                cout << "\nOperation cancelled." << endl;
                waitForEnter();
                return;
            }
        }

        cout << "\nEncrypting..." << endl;

        // Encryption (split into blocks if needed)
        auto encryptedBlocks = RSAUtils::encryptString(message, *currentPublicKey);

        cout << "Generated " << encryptedBlocks.size() << " encrypted blocks" << endl;

        if (showDetailedOutput) {
            for (size_t i = 0; i < encryptedBlocks.size(); ++i) {
                cout << "Block " << i << ": " << encryptedBlocks[i]->toHex() << endl;
            }
        }

        // Save result
        ofstream outFile(outputFile);
        if (!outFile.is_open()) {
            throw runtime_error("Cannot create file: " + outputFile);
        }

        for (const auto& block : encryptedBlocks) {
            outFile << block->toHex() << endl;
        }
        outFile.close();

        cout << "\nFile encrypted successfully!" << endl;
        cout << "Output saved to: " << outputFile << endl;

    }
    catch (const exception& e) {
        cout << "\nError during file encryption: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::decryptFromFile() {
    if (!hasKeys) {
        cout << "\nError: No keys loaded." << endl;
        waitForEnter();
        return;
    }

    clearScreen();
    printHeader("DECRYPT FROM FILE");

    try {
        string inputFile, outputFile;

        cout << "\nEnter input filename (encrypted): ";
        getline(cin, inputFile);

        cout << "Enter output filename: ";
        getline(cin, outputFile);

        if (inputFile.empty() || outputFile.empty()) {
            cout << "\nError: Filenames cannot be empty." << endl;
            waitForEnter();
            return;
        }

        // Check if input file exists
        if (!FileHandler::fileExists(inputFile)) {
            cout << "\nError: Input file does not exist." << endl;
            waitForEnter();
            return;
        }

        // Check if output file exists
        if (FileHandler::fileExists(outputFile)) {
            cout << "\nWarning: Output file already exists." << endl;
            cout << "Overwrite? (y/n): ";

            string input;
            getline(cin, input);

            if (input != "y" && input != "Y") {
                cout << "\nOperation cancelled." << endl;
                waitForEnter();
                return;
            }
        }

        cout << "\nReading encrypted file..." << endl;

        // Read encrypted blocks from file
        ifstream inFile(inputFile);
        if (!inFile.is_open()) {
            throw runtime_error("Cannot open file: " + inputFile);
        }

        vector<shared_ptr<BigInt>> encryptedBlocks;
        string line;

        while (getline(inFile, line)) {
            if (!line.empty() && line[0] != '#') {
                BigInt block(line);
                encryptedBlocks.push_back(make_shared<BigInt>(block));
            }
        }
        inFile.close();

        cout << "Read " << encryptedBlocks.size() << " encrypted blocks" << endl;

        cout << "\nDecrypting..." << endl;

        // Decryption
        string decryptedMessage = RSAUtils::decryptToString(encryptedBlocks, *currentPrivateKey);

        // Save result
        vector<uint8_t> outputBytes(decryptedMessage.begin(), decryptedMessage.end());
        FileHandler::writeMessageToFile(outputFile, outputBytes);

        cout << "\nFile decrypted successfully!" << endl;
        cout << "Output saved to: " << outputFile << endl;
        cout << "Decrypted size: " << outputBytes.size() << " bytes" << endl;

        if (showDetailedOutput && outputBytes.size() < 1000) {
            cout << "\nPreview (first 500 chars):" << endl;
            cout << "==========================" << endl;

            size_t previewSize = min(outputBytes.size(), size_t(500));
            string preview(decryptedMessage.begin(),
                decryptedMessage.begin() + previewSize);
            cout << preview << endl;

            if (outputBytes.size() > 500) {
                cout << "... [truncated]" << endl;
            }
            cout << "==========================" << endl;
        }

    }
    catch (const exception& e) {
        cout << "\nError during file decryption: " << e.what() << endl;
    }

    waitForEnter();
}

void ConsoleApp::runAllTests() {
    clearScreen();

    TestSuite::runAllTests();

    waitForEnter();
}

void ConsoleApp::clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void ConsoleApp::printHeader(const string& title) {
    cout << "========================================" << endl;
    cout << "          " << title << endl;
    cout << "========================================" << endl;
}

void ConsoleApp::printSeparator() {
    cout << "----------------------------------------" << endl;
}

void ConsoleApp::waitForEnter() {
    cout << "\nPress Enter to continue...";
    cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
}

void ConsoleApp::showEncodingMenu() {
    clearScreen();
    printHeader("SELECT ENCODING");

    cout << "\nSelect text encoding for the session:\n";
    cout << "1. UTF-8 (supports Russian, English, special characters)\n";
    cout << "2. ASCII/ANSI (English only, faster)\n";
    cout << "3. Auto-detect\n";

    cout << "\nEnter your choice (1-3): ";

    string input;
    getline(cin, input);

    if (input == "1") {
        RSA::setEncoding(true);
        cout << "\nUTF-8 encoding selected.\n";
        cout << "Note: Ensure your console supports UTF-8.\n";

#ifdef _WIN32
        system("chcp 65001 > nul");
        cout << "Console code page set to UTF-8.\n";
#endif
    }
    else if (input == "2") {
        RSA::setEncoding(false);
        cout << "\nASCII/ANSI encoding selected. Use English text only.\n";
    }
    else {
        // Auto-detection: check system locale
        string locale = setlocale(LC_ALL, "");
        if (locale.find("UTF-8") != string::npos ||
            locale.find("utf-8") != string::npos ||
            locale.find("UTF8") != string::npos ||
            locale.find("utf8") != string::npos) {
            RSA::setEncoding(true);
            cout << "\nAuto-detected: UTF-8 encoding enabled.\n";
        }
        else {
            RSA::setEncoding(false);
            cout << "\nAuto-detected: ASCII/ANSI encoding enabled.\n";
        }
    }

    waitForEnter();
}
