#include "console_app.hpp"
#include <iostream>
#include <stdexcept>
#include <locale>

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
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