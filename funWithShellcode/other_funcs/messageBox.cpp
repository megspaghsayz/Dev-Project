#define WIN32_LEAN_AND_MEAN

#pragma warning(disable : 4201) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"
#include <windows.h>

typedef int (WINAPI *FuncMessageBoxA)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType);

typedef HMODULE(WINAPI *FuncLoadLibraryA)(
    _In_z_ LPTSTR lpFileName);

// Write the logic for the primary payload here
VOID ExecutePayload(VOID) {
    FuncLoadLibraryA MyLoadLibraryA;
    FuncMessageBoxA MyMessageBoxA;

    // Strings must be treated as a char array to prevent them from being stored in
    // an .rdata section. In order to maintain position independence, all data must be stored
    // in the same section.
    char user32[] = {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
    char message[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'l', 'r', 'd', '!', 0};
    char caption[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 0};

#pragma warning(push)
#pragma warning(disable : 4055) // Ignore cast warnings
    // Should I be validating that these return a valid address? Yes... Meh.
    MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressWithHash(0x0726774C);

    // Load the User32 DLL (necessary for MessageBox)
    MyLoadLibraryA((LPTSTR)user32);

    // Dynamically locate MessageBoxA using the GetProcAddressWithHash function
    MyMessageBoxA = (FuncMessageBoxA)GetProcAddressWithHash(0x07568345); // Hash for MessageBoxA

    if (MyMessageBoxA != NULL) {
        MyMessageBoxA(NULL, message, caption, MB_OK);
	}
#pragma warning(pop)

    return;
}
