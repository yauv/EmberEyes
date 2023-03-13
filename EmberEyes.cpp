// EmberEyes.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "EmberEyes.h"
#include "Brc4.h"

void EmberEyes::PrintBannerHelpMenu()
{
	PrintBanner();
	PrintHelpMenu();
}

void EmberEyes::PrintBanner()
{
	printf("\
 _____       ___  ___   _____   _____   _____    _____  __    __  _____   _____ \n\
| ____|     /   |/   | |  _  \\ | ____| |  _  \\  | ____| \\ \\  / / | ____| /  ___/ \n\
| |__      / /|   /| | | |_| | | |__   | |_| |  | |__    \\ \\/ /  | |__   | |___	\n\
| __|     / / |__/ | | |  _  } | __|   |  _  /  |  __ |   \\  /   |  __ |  \\___ \\ \n\
| |___   / /       | | | |_| | | |___  | | \\ \\  | |___    / /    | |___   ___| | \n\
|_____| /_/        |_| |_____/ |_____| |_|  \\_\\ |_____|  /_/     |_____| /_____/ \n\n");

	printf("EmberEyes Version：%s\n", EMBEREYES_VERSION);
	printf("GitHub：https://github.com/yauv/EmberEyes\n\n");
}

void EmberEyes::PrintHelpMenu()
{
	printf("-s		Scan all process memory for suspicious VirtualProtect Context memory to look for SleepConfusion Process.\n\n");
	printf("-e		Extract the Badger Core Dll or configuration file of the Brute Ratel C4 version 1.2.2 payload.\n");
	printf("		EXAMPLES：EmberEyes.exe -e <BadgerPayloadPath>\n\n");
	printf("-p		Parse and print Badger Config to the console.\n");
	printf("		EXAMPLES：EmberEyes.exe -p <BadgerConfigPath>\n\n");
	printf("-f		Online a specified number of fake Badgers.\n");
	printf("		EXAMPLES：EmberEyes.exe -f <BadgerConfigPath> <number>\n\n");
	printf("-d		Used to decrypt Brc4 custom encryption algorithm data encoded by Base64.\n");
	printf("		EXAMPLES：EmberEyes.exe -d <EncKey> <Base64Data>\n\n");
}
/// <summary>
/// Rc4 encrypt or decrypt.
/// </summary>
/// <param name="pbData">Data to be encrypted or decrypted</param>
/// <param name="dwDataLength">Data size to be encrypted or decrypted</param>
/// <param name="pbRc4Key">Rc4 encryption key</param>
/// <returns></returns>
BOOL EmberEyes::Rc4(PBYTE pbData, DWORD dwDataLength, PBYTE pbRc4Key)
{
	if (!pbData || !pbRc4Key)
		return false;

	ustring uData = { 0 };
	ustring uKey = { 0 };
	// get SystemFunction033 Address
	IMPORTAPI(L"advapi32.dll", SystemFunction032, NTSTATUS,
		struct ustring* data,
		const struct ustring* key);
	// data
	uData.lpBuffer = pbData;
	uData.dwMaximumLength = uData.dwLength = dwDataLength;
	// Rc4 KEY
	uKey.lpBuffer = pbRc4Key;
	uKey.dwMaximumLength = uKey.dwLength = sizeof(pbRc4Key);
	// Rc4 Decrypt or Encrypt
	SystemFunction032(&uData, &uKey);
	return true;
}

/// <summary>
/// base64 encoding or decoding.
/// </summary>
/// <param name="bSign">The BASE64_ENCODE flag is used for encoding, and the BASE64_DECODE flag is used for decoding</param>
/// <param name="lpData">base64 encode or decode data</param>
/// <param name="dwDataLength">base64 encoded or decoded data size</param>
/// <param name="pcchString">Returns the data size after base64 encoding or decryption</param>
/// <returns></returns>
PBYTE EmberEyes::Base64(bool bSign, char* lpData, DWORD dwDataLength, DWORD& pcchString)
{
	if (!lpData)
		return nullptr;

	PBYTE pszString = nullptr;
	// base64 Encode
	if (bSign == BASE64_ENCODE) 
	{
		// Get the base64 encoded size
		if (!CryptBinaryToStringA((BYTE*)lpData, dwDataLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &pcchString))
		{
			PrintErrorMsg("CryptBinaryToStringA");
			return nullptr;
		}
		pszString = MVirtualAlloc(pcchString, PAGE_READWRITE);
		if (!pszString)
			return nullptr;
		// base64 Encode
		if (!CryptBinaryToStringA((BYTE*)lpData, dwDataLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (LPSTR)pszString, &pcchString))
		{
			PrintErrorMsg("CryptBinaryToStringA");
			MVirtualFree(pszString);
			return nullptr;
		}
		return pszString;
	}
	// base64 Decode
	else if (bSign == BASE64_DECODE) 
	{
		// Get base64 decoded size
		if (!CryptStringToBinaryA(lpData, 0, CRYPT_STRING_BASE64, NULL, &pcchString, NULL, NULL))
		{
			PrintErrorMsg("CryptStringToBinaryA");
			return nullptr;
		}
		pszString = MVirtualAlloc(pcchString, PAGE_READWRITE);
		if (!pszString)
			return nullptr;
		// base64 Decode
		if (!CryptStringToBinaryA(lpData, strlen(lpData), CRYPT_STRING_BASE64, pszString, &dwDataLength, NULL, NULL)) 
		{
			PrintErrorMsg("CryptStringToBinaryA");
			MVirtualFree(pszString);
			return nullptr;
		}
		return pszString;
	}
	return nullptr;
}

/// <summary>
/// Use the VirtualAlloc function to apply for virtual memory of a specified size or memory permission.
/// </summary>
/// <param name="dwSize">The size of virtual memory to apply</param>
/// <param name="dwProtect">The virtual memory operation permission to apply for</param>
/// <returns></returns>
PBYTE EmberEyes::MVirtualAlloc(DWORD dwSize, DWORD dwProtect)
{
	PBYTE lpAddress = (PBYTE)VirtualAlloc(0, dwSize, MEM_RESERVE | MEM_COMMIT, dwProtect);
	if (lpAddress)
		return lpAddress;

	PrintErrorMsg("VirtualAlloc");
	return nullptr;
}

/// <summary>
/// Used to release the virtual memory space applied by the VirtualAlloc function.
/// </summary>
/// <param name="lpAddress">virtual memory address to free</param>
void EmberEyes::MVirtualFree(PBYTE lpAddress)
{
	if (lpAddress)
		VirtualFree(lpAddress, 0, MEM_RELEASE);
}

/// <summary>
/// Read the specified path file data into the virtual memory.
/// </summary>
/// <param name="cpFilePath">file path to read</param>
/// <param name="pbFileBuffer">Return read file data virtual memory</param>
/// <param name="dwFileSize">Returns the read file data size</param>
/// <returns></returns>
BOOL EmberEyes::MReadFile(const char* cpFilePath, PBYTE& pbFileBuffer, DWORD& dwFileSize)
{
	BOOL bResult = true;
	OVERLAPPED ol = { 0 };
	HANDLE hFile = CreateFileA(cpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PrintErrorMsg("CreateFileA");
		return false;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0)
	{
		printf("[!] This file is empty\n");
		CleanupError();
	}
	pbFileBuffer = MVirtualAlloc(dwFileSize, PAGE_READWRITE);
	if (!pbFileBuffer)
	{
		CleanupError();
	}
	if (!ReadFileEx(hFile, pbFileBuffer, dwFileSize, &ol, 0))
	{
		PrintErrorMsg("ReadFileEx");
		MVirtualFree(pbFileBuffer);
		CleanupError();
	}
CLEAR_EXIT:
	DeleteHandle(hFile);
	return bResult;
}

/// <summary>
/// Write the specified memory data to the file
/// </summary>
/// <param name="cpFilePath">write filename</param>
/// <param name="pbBuffer">memory data to write to the file</param>
/// <param name="dwSize">The size of the memory data to write to the file</param>
/// <returns></returns>
BOOL EmberEyes::MWriteFile(const char* cpFilePath, PBYTE pbBuffer, DWORD dwSize)
{
	BOOL bResult = true;
	DWORD dwBytesWritten = 0;
	if (!cpFilePath || !pbBuffer)
		return false;
	// open file
	HANDLE hCreatFile = CreateFileA(cpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCreatFile == INVALID_HANDLE_VALUE) 
	{
		PrintErrorMsg("CreateFileA");
		CleanupError();
	}
	// write file
	if (!WriteFile(hCreatFile, pbBuffer, dwSize, &dwBytesWritten, NULL)) 
	{
		PrintErrorMsg("WriteFile");
		CleanupError();
	}

CLEAR_EXIT:
	DeleteHandle(hCreatFile);
	return bResult;
}

/// <summary>
/// return LastErrorCode
/// </summary>
/// <param name="pbErrorMsg">error message</param>
void EmberEyes::PrintErrorMsg(const char* pbErrorMsg)
{
	printf("[!] %s LastErrorCode：%d\n", pbErrorMsg, GetLastError());
}
