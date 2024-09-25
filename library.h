#ifndef PASSTOME_LIBRARY_H
#define PASSTOME_LIBRARY_H

#include <Windows.h>
#include <ntsecapi.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function to initialize the DLL when it's loaded
__declspec(dllexport) BOOLEAN __stdcall InitializeChangeNotify(void);

// Function called when a user attempts to change their password
// uname: The user's account (signin) name
// legalName: The user's full name
// password: The proposed new password
// SetOperation: TRUE if the operation is setting a new password, FALSE if it’s a password change
// Returns: TRUE to allow the password change, FALSE to deny it
__declspec(dllexport) BOOLEAN __stdcall PasswordFilter(
        PUNICODE_STRING uname,
        PUNICODE_STRING legalName,
        PUNICODE_STRING password,
        BOOLEAN SetOperation
);

// Function to notify that a password change has successfully occurred
// uname: The user's account name
// RelativeId: The user's Relative Identifier (RID)
// password: The newly set password
// Returns: 0 for success, other NTSTATUS code for error
__declspec(dllexport) NTSTATUS __stdcall PasswordChangeNotify(
        UNICODE_STRING *uname,
        ULONG RelativeId,
        PUNICODE_STRING password
);

#ifdef __cplusplus
}
#endif

#endif //PASSTOME_LIBRARY_H
