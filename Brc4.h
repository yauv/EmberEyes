#pragma once

#include "EmberEyes.h"
#include <format>
#include <random>
#include <wininet.h>

#pragma comment(lib,"Wininet.lib")

#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

#define RC4_KEY_LENGTH 8

#define BASE64_DECODE false
#define BASE64_ENCODE true

#define SMB_BADGER 4
#define TCP_BADGER 5
#define STAGE_BADGER 11
#define HTTP_DOH_BADGER 18

typedef struct Finding
{
	DWORD pid;
	std::wstring processName;
	std::string details;
	Finding() : pid(0) {}
}Finding;
typedef std::unique_ptr<Finding> UPFinding;
extern std::vector<UPFinding> Findings;

typedef struct Brc4Config
{
	DWORD sleepObfuscation;
	DWORD sleepTime;
	DWORD jitterTime;
	std::string pipeName;
	std::string proxy;
	std::vector <std::string> vDnsHosts;
	std::string checkInARecord;
	std::string idleARecord;
	std::string prepended;
	std::string appended;
	std::string spoofedTxTRecord;
	std::string rotationalHosts;
	BOOL dieIfC2Offline;
	BOOL ssl;
	std::vector <std::string> vHost;
	DWORD port;
	std::string userAgent;
	std::string authKey;
	std::string encKey;
	std::vector <std::string> vURIs;
	std::vector <std::string> vExtraHeaders;
	std::string onlinePack;
}Brc4Config;
typedef std::unique_ptr<Brc4Config> UPBrc4Config;
extern std::vector<UPBrc4Config> vBrc4Config;

class Brc4 : protected EmberEyes
{
public:
	// Brc4 custom Encryption Algorithm
	BOOL EncryptData(PBYTE pbKey, PBYTE pbData, DWORD& dwDataLength);
	// Brc4 Custom Decryption Algorithm
	BOOL DecryptData(PBYTE pbKey, PBYTE pbData, DWORD dwDataLength);
	// Scans all system process memory for suspicious VirtualProtect Context memory processes
	void ScanAllProcessMem();
	// Extract Config and Badger Core Dll from Badger Payload
	BOOL Brc4ConfigExtract(const char* cpFilePath);
	// Parse and print Badger Config to the console
	BOOL PrintBrc4Config(const char* cpFilePath);
	// Fake online Badger
	BOOL FakeOnlineBrc4Badger(const char* lpConfigPath, DWORD dwCount);
	// Decrypt the Base64 Encoded Brc4 Custom Encryption Algorithm data
	BOOL DecryptBase64Brc4Encrypt(char* enckey, char* base64);
private:
	BYTE g_bKey[176] = { 0 };
	BYTE g_bTemp[4] = { 0 };
	DWORD g_replaceIndex = 1;
protected:
	// Brc4 Data Encryption Algorithm
	void InitXorKeyBox();
	void replaceFourByteKey(unsigned char* fourByteKey);
	void MyXor(unsigned char* key, unsigned char* data);
	void replaceBoxData(unsigned char* data);
	void ByteOutOfOrder(unsigned char* data);
	void boxXorData(unsigned char* data);
	// Decrypt
	void DeByteOutOfOrder(unsigned char* data);
	void DereplaceBoxData(unsigned char* data);
	void DeboxXorData(unsigned char* data);

	// dump x64 badger core dll and config
	BOOL DumpX64BadgerCoreConfig(std::vector<ptr_t>& vptr);
	// dump x64 stage config
	BOOL DumpX64StageConfig(std::vector<ptr_t>& vptr);
	// dump x86 badger core dll and config
	BOOL DumpX86BadgerCoreConfig(std::vector<ptr_t>& vptr);
	// dump x86 stage config
	BOOL DumpX86StageConfig(std::vector<ptr_t>& vptr);

	// Badger Config
	DWORD GetConfigTypeNumber(PBYTE pbConfig, DWORD dwConfigSize);
	DWORD CheckMultipleFields(PBYTE pbConfig);
	BOOL ParseMultipleConfigFields(PBYTE& pbConfig, DWORD dwConfigSize, std::vector<std::string>& vString);
	PBYTE ParseConfigFields(PBYTE& pbConfig, DWORD dwConfigSize);
	DWORD AsciiToHex(PBYTE pbConfig);
	BOOL ParseBrc4SmbConfig(PBYTE pbConfig, DWORD dwConfigSize);
	BOOL ParseBrc4TcpConfig(PBYTE pbConfig, DWORD dwConfigSize);
	BOOL ParseBrc4StageConfig(PBYTE pbConfig, DWORD dwConfigSize);
	BOOL ParseBrc4HTTPDOHConfig(PBYTE pbConfig, DWORD dwConfigSize);
	void PrintBrc4ConfigToConsole(DWORD dwConfigType);
	void RandomOnlinePack(PBYTE pbOnlinePack);
	BOOL SendHTTPReqToC2();

	// find suspicious VirtualProtect Context
	void PrintFindSuspiciousContext();
	static BOOL inline IsExecuteSet(DWORD dwProtect);
	static BOOL inline VirtualProtectFunction(void** vpFunctions, int iCount, DWORD64 dwFunction);
	BOOL FindSuspiciousContext(ProcessInfo& processInfo, void* pBuf, SIZE_T szBuf);
};

