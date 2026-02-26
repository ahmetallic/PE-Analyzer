#ifndef PEANALYZER_H
#define PEANALYZER_H

#include <string>
#include <vector>
#include <windows.h>

class PEAnalyzer {
public:
    PEAnalyzer();
    ~PEAnalyzer();

    bool LoadFile(const std::string& filePath);

    void PrintDosHeaderInfo() const;
    void PrintNtHeadersInfo() const;
    void PrintSectionHeaders() const;

private:
    std::string m_filePath;
    HANDLE m_hFile;
    HANDLE m_hFileMapping;
    LPVOID m_lpFileBase;

    PIMAGE_DOS_HEADER m_pDosHeader;
    PIMAGE_NT_HEADERS m_pNtHeaders;

    void Cleanup();

    std::string TimeStampToString(DWORD timeStamp) const;
};

#endif // PEANALYZER_H