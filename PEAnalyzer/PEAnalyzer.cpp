#include "PEAnalyzer.h"
#include <iostream>
#include <ctime>
#include <iomanip>

PEAnalyzer::PEAnalyzer() : 
    m_hFile(INVALID_HANDLE_VALUE), 
    m_hFileMapping(NULL), 
    m_lpFileBase(NULL), 
    m_pDosHeader(nullptr), 
    m_pNtHeaders(nullptr) 
{
}

PEAnalyzer::~PEAnalyzer() {
    Cleanup();
}

void PEAnalyzer::Cleanup() {
    if (m_lpFileBase) UnmapViewOfFile(m_lpFileBase);
    if (m_hFileMapping) CloseHandle(m_hFileMapping);
    if (m_hFile != INVALID_HANDLE_VALUE) CloseHandle(m_hFile);
    
    m_lpFileBase = NULL;
    m_hFileMapping = NULL;
    m_hFile = INVALID_HANDLE_VALUE;
}

bool PEAnalyzer::LoadFile(const std::string& filePath) {
    Cleanup(); // clear any previous file
    m_filePath = filePath;

    // Open
    m_hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Error: Could not open file: " << filePath << std::endl;
        return false;
    }

    // File Mapping
    m_hFileMapping = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m_hFileMapping) {
        std::cerr << "[!] Error: Could not create file mapping." << std::endl;
        Cleanup();
        return false;
    }

    // Map View
    m_lpFileBase = MapViewOfFile(m_hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_lpFileBase) {
        std::cerr << "[!] Error: Could not map view of file." << std::endl;
        Cleanup();
        return false;
    }

    // 4. Parse DOS Header
    m_pDosHeader = (PIMAGE_DOS_HEADER)m_lpFileBase;
    if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Error: Invalid DOS Signature (Not a valid executable)." << std::endl;
        Cleanup();
        return false;
    }

    // 5. Parse The PE Header
    // The DOS header contains 'e_lfanew', which is the offset to the NT headers
    m_pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)m_lpFileBase + m_pDosHeader->e_lfanew);
    if (m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Error: Invalid NT Signature (Not a valid PE file)." << std::endl;
        Cleanup();
        return false;
    }

    return true;
}

std::string PEAnalyzer::TimeStampToString(DWORD timeStamp) const {
    time_t rawTime = (time_t)timeStamp;
    struct tm timeInfo;
    char buffer[80];
    
    // Use secure version of localtime
    localtime_s(&timeInfo, &rawTime); 
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);
    return std::string(buffer);
}

void PEAnalyzer::PrintDosHeaderInfo() const {
    if (!m_pDosHeader) return;
    std::cout << "\n=== DOS HEADER ===" << std::endl;
    std::cout << "Magic Number: " << std::hex << m_pDosHeader->e_magic << std::dec << " (MZ)" << std::endl;
    std::cout << "Offset to NT Headers: 0x" << std::hex << m_pDosHeader->e_lfanew << std::dec << std::endl;
}

void PEAnalyzer::PrintNtHeadersInfo() const {
    if (!m_pNtHeaders) return;
    std::cout << "\n=== NT HEADERS ===" << std::endl;
    std::cout << "Signature: " << std::hex << m_pNtHeaders->Signature << std::dec << " (PE)" << std::endl;
    
    // File Header Info
    std::cout << "Machine Arch: 0x" << std::hex << m_pNtHeaders->FileHeader.Machine << std::dec;
    if (m_pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) std::cout << " (x64)";
    else if (m_pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) std::cout << " (x86)";
    std::cout << std::endl;

    std::cout << "Number of Sections: " << m_pNtHeaders->FileHeader.NumberOfSections << std::endl;
    std::cout << "Time Stamp: " << TimeStampToString(m_pNtHeaders->FileHeader.TimeDateStamp) << std::endl;
    
    // Optional Header Info
    std::cout << "Entry Point Address: 0x" << std::hex << m_pNtHeaders->OptionalHeader.AddressOfEntryPoint << std::dec << std::endl;
    std::cout << "Image Base: 0x" << std::hex << m_pNtHeaders->OptionalHeader.ImageBase << std::dec << std::endl;
}

void PEAnalyzer::PrintSectionHeaders() const {
    if (!m_pNtHeaders) return;

    std::cout << "\n=== SECTION HEADERS ===" << std::endl;
    std::cout << std::left << std::setw(10) << "Name" 
              << std::setw(15) << "Virtual Size" 
              << std::setw(15) << "Virtual Addr" 
              << std::setw(15) << "Raw Size" << std::endl;
    std::cout << "-------------------------------------------------------" << std::endl;

    // The first section header is located immediately after the Optional Header
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeaders);

    for (int i = 0; i < m_pNtHeaders->FileHeader.NumberOfSections; ++i) {
        // Section names are not always null-terminated, so we must handle them carefully
        char name[9] = {0};
        memcpy(name, pSectionHeader->Name, 8);

        std::cout << std::left << std::setw(10) << name
                  << "0x" << std::hex << std::setw(13) << pSectionHeader->Misc.VirtualSize
                  << "0x" << std::setw(13) << pSectionHeader->VirtualAddress
                  << "0x" << std::setw(13) << pSectionHeader->SizeOfRawData << std::dec << std::endl;

        pSectionHeader++; // Move pointer to next section
    }
}