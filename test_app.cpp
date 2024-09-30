//
// Asa Horn
// aoh9470@rit.edu
//

//Simple main program to test the functions of my dll

#include "library.h"

void InitUnicodeString(PUNICODE_STRING pUnicodeString, const wchar_t* wszString) {
    if (wszString) {
        size_t len = wcslen(wszString);
        pUnicodeString->Buffer = const_cast<PWSTR>(wszString);
        pUnicodeString->Length = (USHORT)(len * sizeof(wchar_t));
        pUnicodeString->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    } else {
        pUnicodeString->Buffer = nullptr;
        pUnicodeString->Length = 0;
        pUnicodeString->MaximumLength = 0;
    }
}

int main() {
    // Prepare test data
    UNICODE_STRING username, password;
    InitUnicodeString(&username, L"testuser");
    InitUnicodeString(&password, L"passworddd-15");
    ULONG relativeId = 12345;

    // call my function (he gets lonely)
    PasswordChangeNotify(&username, 00, &password);

    return 0;
}