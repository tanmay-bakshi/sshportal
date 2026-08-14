#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    WCHAR marker[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(
        L"SSHPORTAL_REJECTED_WINTUN_MARKER",
        marker,
        MAX_PATH
    );
    if (length == 0 || length >= MAX_PATH) {
        return TRUE;
    }

    HANDLE file = CreateFileW(
        marker,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    return TRUE;
}
