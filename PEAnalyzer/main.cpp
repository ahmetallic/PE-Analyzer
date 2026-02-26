#include <iostream>
#include "PEAnalyzer.h"

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "   PE-Analyzer: Binary Analysis Tool   " << std::endl;
    std::cout << "========================================" << std::endl;

    if (argc != 2) {
        std::cout << "Usage: PEAnalyzer.exe <path_to_executable>" << std::endl;
        std::cout << "Example: PEAnalyzer.exe C:\\Windows\\System32\\notepad.exe" << std::endl;
        return 1;
    }

    std::string targetFile = argv[1];
    PEAnalyzer analyzer;

    std::cout << "Analyzing: " << targetFile << "...\n";

    if (analyzer.LoadFile(targetFile)) {
        analyzer.PrintDosHeaderInfo();
        analyzer.PrintNtHeadersInfo();
        analyzer.PrintSectionHeaders();
    } else {
        std::cout << "Analysis failed." << std::endl;
        return 1;
    }

    return 0;
}