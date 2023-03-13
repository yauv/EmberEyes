#pragma once
#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <iostream>
#include <wincrypt.h>

#pragma comment(lib,"Crypt32.lib")

using namespace blackbone;

const char EMBEREYES_VERSION[] = "v0.1";

#define DeleteHandle(x)                 \
    if (x && x != INVALID_HANDLE_VALUE) \
    {                                   \
        CloseHandle(x);                 \
        x = 0;                          \
    }

#define DeleteWinINetHandle(x)          \
    if (x)                              \
    {                                   \
        InternetCloseHandle(x);         \
        x = 0;                          \
    }

#define CleanupError()      \
    bResult = false;        \
    goto CLEAR_EXIT;

#define CleanupSuccess()    \
    bResult = true;         \
    goto CLEAR_EXIT;

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);

typedef struct ustring
{
	DWORD dwLength;
	DWORD dwMaximumLength;
	LPVOID lpBuffer;
}ustring;

class EmberEyes {
public:
    void PrintBannerHelpMenu();
protected:
    void PrintBanner();
    void PrintHelpMenu();
    BOOL Rc4(PBYTE pbData, DWORD dwDataLength, PBYTE pbRc4Key);
	PBYTE Base64(bool bSign, char* lpData, DWORD dwDataLength, DWORD& pcchString);
	PBYTE MVirtualAlloc(DWORD dwSize,DWORD dwProtect);
	void MVirtualFree(PBYTE lpAddress);
	BOOL MReadFile(const char* cpFilePath,PBYTE& pbFileBuffer,DWORD& dwFileSize);
	BOOL MWriteFile(const char* cpFilePath, PBYTE pbBuffer, DWORD dwSize);
	void PrintErrorMsg(const char* pbErrorMsg);
};