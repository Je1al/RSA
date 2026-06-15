#ifndef CONSOLE_APP_HPP
#define CONSOLE_APP_HPP

#include "rsa.hpp"
#include "file_handler.hpp"
#include "utils.hpp"
#include <memory>
#include <string>

// Console application for demonstrating RSA functionality
class ConsoleApp {
public:
    ConsoleApp();
    ~ConsoleApp();

    // Application launch
    void run();

    void showEncodingMenu();

private:
    // Main menu
    void showMainMenu();
    void handleMainMenuChoice(int choice);

    // Submenus
    void showKeyMenu();
    void showEncryptionMenu();
    void showDecryptionMenu();
    void showFileMenu();
    void showTestMenu();

    // Operation handlers
    void generateKeys();
    void loadKeysFromFile();
    void saveKeysToFile();
    void showCurrentKeys();

    void encryptManual();
    void encryptFromFile();

    void decryptManual();
    void decryptFromFile();

    void runAllTests();

    // Helper methods
    void clearScreen();
    void printHeader(const std::string& title);
    void printSeparator();
    void waitForEnter();

    // Current keys
    std::unique_ptr<RSA::PublicKey> currentPublicKey;
    std::unique_ptr<RSA::PrivateKey> currentPrivateKey;
    bool hasKeys;

    // Configuration
    bool showDetailedOutput;
};

#endif // CONSOLE_APP_HPP
