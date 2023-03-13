#include "Brc4.h"

std::vector<UPFinding> Findings;
std::vector<UPBrc4Config> vBrc4Config;

/*
	* x64 Badger Shellcode Start
	41 5F          pop     r15
	55             push    rbp
	50             push    rax
	53             push    rbx
	51             push    rcx
	52             push    rdx
	56             push    rsi
	57             push    rdi
	41 50          push    r8
	41 51          push    r9
	41 52          push    r10
	41 53          push    r11
	41 54          push    r12
	41 55          push    r13
	41 56          push    r14
	41 57          push    r15
	48 89 E5       mov     rbp, rsp
	48 83 E4 F0    and     rsp, 0FFFFFFFFFFFFFFF0h
	48 31 C0       xor     rax, rax
	50             push    rax
	*/
std::vector<uint8_t> uiPattern_X64_Start = { 
	0x41, 0x5F, 0x55, 0x50, 0x53, 0x51, 0x52, 0x56,
	0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
	0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
	0x57, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0,
	0x48, 0x31, 0xC0, 0x50 };

/*
* x64 Badger Shellcode Base64 Config end
48 89 E1       mov     rcx, rsp
68 ?? ?? ?? ?? push    ???h
5A             pop     rdx
*/
std::vector<uint8_t> uiPattern_X64_Config_End = {
	0x48, 0x89, 0xE1, 0x68, 0x63, 0x63, 0x63, 0x63, 0x5A
};

// mov RAX/RBX/RCX/RDX/RBP/RSP/RSI/RDI , IMM64
// push RAX/RBX/RCX/RDX/RBP/RSP/RSI/RDI
std::vector<uint8_t> uiPattern_X64_RAX_RDI = {
	0x48, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63 
};

// mov R8/R9/R10/R11/R12/R13/R14/R15 , IMM64
// push R8/R9/R10/R11/R12/R13/R14/R15
std::vector<uint8_t> uiPattern_X64_R8_R15 = {
	0x49, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x41, 0x63 
};

/*
* mov eax, ????????ｈ
* push eax
*/
std::vector<uint8_t> uiPattern_X64_MOV_EAX = {
	0xB8, 0x63, 0x63, 0x63, 0x63, 0x50 
};

/*
* x64 Badger Shellcode Core Data end
49 89 E0       mov     r8, rsp
68 10 94 03 00 push    39410h
41 59          pop     r9
*/
std::vector<uint8_t> uiPattern_X64_Core_End = {
	0x49, 0x89, 0xE0, 0x68, 0x63, 0x63, 0x63, 0x63, 0x41, 0x59 
};

/*
48 B8 7B 22 61 72 63 68 22 3A mov     rax, 3A2268637261227Bh ; {"arch":
55                            push    rbp
48 BA 36 34 2C 22 63 64 73 22 mov     rdx, 22736463222C3436h ; 64,"cds"
48 89 E5                      mov     rbp, rsp
41 57                         push    r15
41 56                         push    r14
41 55                         push    r13
41 54                         push    r12
57                            push    rdi
56                            push    rsi
53                            push    rbx
*/
std::vector<uint8_t> uiPattern_X64_Stage = {
	0x48, 0xB8, 0x7B, 0x22, 0x61, 0x72, 0x63, 0x68, 
	0x22, 0x3A, 0x55, 0x48, 0xBA, 0x36, 0x34, 0x2C, 
	0x22, 0x63, 0x64, 0x73, 0x22, 0x48, 0x89, 0xE5, 
	0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 
	0x57, 0x56, 0x53
};


/*
* x86 Badger Shellcode Start
5B				pop     ebx
60				pusha
89 E5			mov     ebp, esp
83 E4 F8		and     esp, 0FFFFFFF8h
31 C0			xor     eax, eax
50				push    eax
*/
std::vector<uint8_t> uiPattern_X86_Start = {
	0x5B, 0x60, 0x89, 0xE5, 0x83, 0xE4, 0xF8, 0x31, 0xC0, 0x50 
};


/*
* x86 Badger Core End
89 E6          mov     esi, esp
68 ?? ?? ?? ?? push    ?????h
5F             pop     edi
*/
std::vector<uint8_t> uiPattern_X86_Core_End = {
	0x89, 0xE6, 0x68, 0x63, 0x63, 0x63, 0x63, 0x5F
};

/*
* x86 Badger Base64 End
89 E1			mov     ecx, esp
68 ?? ?? ?? ??  push    ???h
5A				pop     edx
*/
std::vector<uint8_t> uiPattern_X86_Config_End = {
	0x89, 0xE1, 0x68, 0x63, 0x63, 0x63, 0x63, 0x5A
};

/*
* mov eax,????h
* push eax
*/
std::vector<uint8_t> uiPattern_X86_MOV_EAX_PUSH = {
	0xB8, 0x63, 0x63, 0x63, 0x63, 0x50 
};

/*
* mov edi,????h
* push edi
*/
std::vector<uint8_t> uiPattern_X86_MOV_EDI_PUSH = {
	0xBF, 0x63, 0x63, 0x63, 0x63, 0x57 
};

/*
* mov esi,????h
* push esi
*/
std::vector<uint8_t> uiPattern_X86_MOV_ESI_PUSH = {
	0xBE, 0x63, 0x63, 0x63, 0x63, 0x56 
};


/*
* mov ecx,????h
* push ecx
*/
std::vector<uint8_t> uiPattern_X86_MOV_ECX_PUSH = {
	0xB9, 0x63, 0x63, 0x63, 0x63, 0x51 
};

/*
* mov edx,????h
* push edx
*/
std::vector<uint8_t> uiPattern_X86_MOV_EDX_PUSH = {
	0xBA, 0x63, 0x63, 0x63, 0x63, 0x52 
};


/* Encrpyt Box */

unsigned char g_Box1[] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char g_Box2[] =
{
	0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
	0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
	0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A,
	0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
	0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF,
	0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC,
	0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,
	0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3,
	0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94,
	0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35,
	0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F,
	0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
	0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD,
	0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D
};


unsigned char g_box3[] =
{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
	0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
	0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
	0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
	0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
	0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
	0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
	0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
	0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
	0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
	0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
	0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
};


unsigned char g_box4[] =
{
	0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11,
	0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21,
	0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71,
	0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41,
	0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1,
	0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1,
	0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1,
	0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81,
	0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A,
	0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA,
	0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA,
	0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA,
	0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A,
	0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A,
	0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A,
	0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A
};


/* Decrypt Box*/

unsigned char g_DereplaceFourKeyBox[] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char g_DeBox1[] =
{
	0x00, 0x0E, 0x1C, 0x12, 0x38, 0x36, 0x24, 0x2A, 0x70, 0x7E, 0x6C, 0x62, 0x48, 0x46, 0x54, 0x5A,
	0xE0, 0xEE, 0xFC, 0xF2, 0xD8, 0xD6, 0xC4, 0xCA, 0x90, 0x9E, 0x8C, 0x82, 0xA8, 0xA6, 0xB4, 0xBA,
	0xDB, 0xD5, 0xC7, 0xC9, 0xE3, 0xED, 0xFF, 0xF1, 0xAB, 0xA5, 0xB7, 0xB9, 0x93, 0x9D, 0x8F, 0x81,
	0x3B, 0x35, 0x27, 0x29, 0x03, 0x0D, 0x1F, 0x11, 0x4B, 0x45, 0x57, 0x59, 0x73, 0x7D, 0x6F, 0x61,
	0xAD, 0xA3, 0xB1, 0xBF, 0x95, 0x9B, 0x89, 0x87, 0xDD, 0xD3, 0xC1, 0xCF, 0xE5, 0xEB, 0xF9, 0xF7,
	0x4D, 0x43, 0x51, 0x5F, 0x75, 0x7B, 0x69, 0x67, 0x3D, 0x33, 0x21, 0x2F, 0x05, 0x0B, 0x19, 0x17,
	0x76, 0x78, 0x6A, 0x64, 0x4E, 0x40, 0x52, 0x5C, 0x06, 0x08, 0x1A, 0x14, 0x3E, 0x30, 0x22, 0x2C,
	0x96, 0x98, 0x8A, 0x84, 0xAE, 0xA0, 0xB2, 0xBC, 0xE6, 0xE8, 0xFA, 0xF4, 0xDE, 0xD0, 0xC2, 0xCC,
	0x41, 0x4F, 0x5D, 0x53, 0x79, 0x77, 0x65, 0x6B, 0x31, 0x3F, 0x2D, 0x23, 0x09, 0x07, 0x15, 0x1B,
	0xA1, 0xAF, 0xBD, 0xB3, 0x99, 0x97, 0x85, 0x8B, 0xD1, 0xDF, 0xCD, 0xC3, 0xE9, 0xE7, 0xF5, 0xFB,
	0x9A, 0x94, 0x86, 0x88, 0xA2, 0xAC, 0xBE, 0xB0, 0xEA, 0xE4, 0xF6, 0xF8, 0xD2, 0xDC, 0xCE, 0xC0,
	0x7A, 0x74, 0x66, 0x68, 0x42, 0x4C, 0x5E, 0x50, 0x0A, 0x04, 0x16, 0x18, 0x32, 0x3C, 0x2E, 0x20,
	0xEC, 0xE2, 0xF0, 0xFE, 0xD4, 0xDA, 0xC8, 0xC6, 0x9C, 0x92, 0x80, 0x8E, 0xA4, 0xAA, 0xB8, 0xB6,
	0x0C, 0x02, 0x10, 0x1E, 0x34, 0x3A, 0x28, 0x26, 0x7C, 0x72, 0x60, 0x6E, 0x44, 0x4A, 0x58, 0x56,
	0x37, 0x39, 0x2B, 0x25, 0x0F, 0x01, 0x13, 0x1D, 0x47, 0x49, 0x5B, 0x55, 0x7F, 0x71, 0x63, 0x6D,
	0xD7, 0xD9, 0xCB, 0xC5, 0xEF, 0xE1, 0xF3, 0xFD, 0xA7, 0xA9, 0xBB, 0xB5, 0x9F, 0x91, 0x83, 0x8D
};

unsigned char g_DeBox2[] =
{
	0x00, 0x0D, 0x1A, 0x17, 0x34, 0x39, 0x2E, 0x23, 0x68, 0x65, 0x72, 0x7F, 0x5C, 0x51, 0x46, 0x4B,
	0xD0, 0xDD, 0xCA, 0xC7, 0xE4, 0xE9, 0xFE, 0xF3, 0xB8, 0xB5, 0xA2, 0xAF, 0x8C, 0x81, 0x96, 0x9B,
	0xBB, 0xB6, 0xA1, 0xAC, 0x8F, 0x82, 0x95, 0x98, 0xD3, 0xDE, 0xC9, 0xC4, 0xE7, 0xEA, 0xFD, 0xF0,
	0x6B, 0x66, 0x71, 0x7C, 0x5F, 0x52, 0x45, 0x48, 0x03, 0x0E, 0x19, 0x14, 0x37, 0x3A, 0x2D, 0x20,
	0x6D, 0x60, 0x77, 0x7A, 0x59, 0x54, 0x43, 0x4E, 0x05, 0x08, 0x1F, 0x12, 0x31, 0x3C, 0x2B, 0x26,
	0xBD, 0xB0, 0xA7, 0xAA, 0x89, 0x84, 0x93, 0x9E, 0xD5, 0xD8, 0xCF, 0xC2, 0xE1, 0xEC, 0xFB, 0xF6,
	0xD6, 0xDB, 0xCC, 0xC1, 0xE2, 0xEF, 0xF8, 0xF5, 0xBE, 0xB3, 0xA4, 0xA9, 0x8A, 0x87, 0x90, 0x9D,
	0x06, 0x0B, 0x1C, 0x11, 0x32, 0x3F, 0x28, 0x25, 0x6E, 0x63, 0x74, 0x79, 0x5A, 0x57, 0x40, 0x4D,
	0xDA, 0xD7, 0xC0, 0xCD, 0xEE, 0xE3, 0xF4, 0xF9, 0xB2, 0xBF, 0xA8, 0xA5, 0x86, 0x8B, 0x9C, 0x91,
	0x0A, 0x07, 0x10, 0x1D, 0x3E, 0x33, 0x24, 0x29, 0x62, 0x6F, 0x78, 0x75, 0x56, 0x5B, 0x4C, 0x41,
	0x61, 0x6C, 0x7B, 0x76, 0x55, 0x58, 0x4F, 0x42, 0x09, 0x04, 0x13, 0x1E, 0x3D, 0x30, 0x27, 0x2A,
	0xB1, 0xBC, 0xAB, 0xA6, 0x85, 0x88, 0x9F, 0x92, 0xD9, 0xD4, 0xC3, 0xCE, 0xED, 0xE0, 0xF7, 0xFA,
	0xB7, 0xBA, 0xAD, 0xA0, 0x83, 0x8E, 0x99, 0x94, 0xDF, 0xD2, 0xC5, 0xC8, 0xEB, 0xE6, 0xF1, 0xFC,
	0x67, 0x6A, 0x7D, 0x70, 0x53, 0x5E, 0x49, 0x44, 0x0F, 0x02, 0x15, 0x18, 0x3B, 0x36, 0x21, 0x2C,
	0x0C, 0x01, 0x16, 0x1B, 0x38, 0x35, 0x22, 0x2F, 0x64, 0x69, 0x7E, 0x73, 0x50, 0x5D, 0x4A, 0x47,
	0xDC, 0xD1, 0xC6, 0xCB, 0xE8, 0xE5, 0xF2, 0xFF, 0xB4, 0xB9, 0xAE, 0xA3, 0x80, 0x8D, 0x9A, 0x97
};

unsigned char g_DeBox3[] =
{
	0x00, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x3F, 0x48, 0x41, 0x5A, 0x53, 0x6C, 0x65, 0x7E, 0x77,
	0x90, 0x99, 0x82, 0x8B, 0xB4, 0xBD, 0xA6, 0xAF, 0xD8, 0xD1, 0xCA, 0xC3, 0xFC, 0xF5, 0xEE, 0xE7,
	0x3B, 0x32, 0x29, 0x20, 0x1F, 0x16, 0x0D, 0x04, 0x73, 0x7A, 0x61, 0x68, 0x57, 0x5E, 0x45, 0x4C,
	0xAB, 0xA2, 0xB9, 0xB0, 0x8F, 0x86, 0x9D, 0x94, 0xE3, 0xEA, 0xF1, 0xF8, 0xC7, 0xCE, 0xD5, 0xDC,
	0x76, 0x7F, 0x64, 0x6D, 0x52, 0x5B, 0x40, 0x49, 0x3E, 0x37, 0x2C, 0x25, 0x1A, 0x13, 0x08, 0x01,
	0xE6, 0xEF, 0xF4, 0xFD, 0xC2, 0xCB, 0xD0, 0xD9, 0xAE, 0xA7, 0xBC, 0xB5, 0x8A, 0x83, 0x98, 0x91,
	0x4D, 0x44, 0x5F, 0x56, 0x69, 0x60, 0x7B, 0x72, 0x05, 0x0C, 0x17, 0x1E, 0x21, 0x28, 0x33, 0x3A,
	0xDD, 0xD4, 0xCF, 0xC6, 0xF9, 0xF0, 0xEB, 0xE2, 0x95, 0x9C, 0x87, 0x8E, 0xB1, 0xB8, 0xA3, 0xAA,
	0xEC, 0xE5, 0xFE, 0xF7, 0xC8, 0xC1, 0xDA, 0xD3, 0xA4, 0xAD, 0xB6, 0xBF, 0x80, 0x89, 0x92, 0x9B,
	0x7C, 0x75, 0x6E, 0x67, 0x58, 0x51, 0x4A, 0x43, 0x34, 0x3D, 0x26, 0x2F, 0x10, 0x19, 0x02, 0x0B,
	0xD7, 0xDE, 0xC5, 0xCC, 0xF3, 0xFA, 0xE1, 0xE8, 0x9F, 0x96, 0x8D, 0x84, 0xBB, 0xB2, 0xA9, 0xA0,
	0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A, 0x71, 0x78, 0x0F, 0x06, 0x1D, 0x14, 0x2B, 0x22, 0x39, 0x30,
	0x9A, 0x93, 0x88, 0x81, 0xBE, 0xB7, 0xAC, 0xA5, 0xD2, 0xDB, 0xC0, 0xC9, 0xF6, 0xFF, 0xE4, 0xED,
	0x0A, 0x03, 0x18, 0x11, 0x2E, 0x27, 0x3C, 0x35, 0x42, 0x4B, 0x50, 0x59, 0x66, 0x6F, 0x74, 0x7D,
	0xA1, 0xA8, 0xB3, 0xBA, 0x85, 0x8C, 0x97, 0x9E, 0xE9, 0xE0, 0xFB, 0xF2, 0xCD, 0xC4, 0xDF, 0xD6,
	0x31, 0x38, 0x23, 0x2A, 0x15, 0x1C, 0x07, 0x0E, 0x79, 0x70, 0x6B, 0x62, 0x5D, 0x54, 0x4F, 0x46
};

unsigned char g_DeBox4[] =
{
	0x00, 0x0B, 0x16, 0x1D, 0x2C, 0x27, 0x3A, 0x31, 0x58, 0x53, 0x4E, 0x45, 0x74, 0x7F, 0x62, 0x69,
	0xB0, 0xBB, 0xA6, 0xAD, 0x9C, 0x97, 0x8A, 0x81, 0xE8, 0xE3, 0xFE, 0xF5, 0xC4, 0xCF, 0xD2, 0xD9,
	0x7B, 0x70, 0x6D, 0x66, 0x57, 0x5C, 0x41, 0x4A, 0x23, 0x28, 0x35, 0x3E, 0x0F, 0x04, 0x19, 0x12,
	0xCB, 0xC0, 0xDD, 0xD6, 0xE7, 0xEC, 0xF1, 0xFA, 0x93, 0x98, 0x85, 0x8E, 0xBF, 0xB4, 0xA9, 0xA2,
	0xF6, 0xFD, 0xE0, 0xEB, 0xDA, 0xD1, 0xCC, 0xC7, 0xAE, 0xA5, 0xB8, 0xB3, 0x82, 0x89, 0x94, 0x9F,
	0x46, 0x4D, 0x50, 0x5B, 0x6A, 0x61, 0x7C, 0x77, 0x1E, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2F,
	0x8D, 0x86, 0x9B, 0x90, 0xA1, 0xAA, 0xB7, 0xBC, 0xD5, 0xDE, 0xC3, 0xC8, 0xF9, 0xF2, 0xEF, 0xE4,
	0x3D, 0x36, 0x2B, 0x20, 0x11, 0x1A, 0x07, 0x0C, 0x65, 0x6E, 0x73, 0x78, 0x49, 0x42, 0x5F, 0x54,
	0xF7, 0xFC, 0xE1, 0xEA, 0xDB, 0xD0, 0xCD, 0xC6, 0xAF, 0xA4, 0xB9, 0xB2, 0x83, 0x88, 0x95, 0x9E,
	0x47, 0x4C, 0x51, 0x5A, 0x6B, 0x60, 0x7D, 0x76, 0x1F, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2E,
	0x8C, 0x87, 0x9A, 0x91, 0xA0, 0xAB, 0xB6, 0xBD, 0xD4, 0xDF, 0xC2, 0xC9, 0xF8, 0xF3, 0xEE, 0xE5,
	0x3C, 0x37, 0x2A, 0x21, 0x10, 0x1B, 0x06, 0x0D, 0x64, 0x6F, 0x72, 0x79, 0x48, 0x43, 0x5E, 0x55,
	0x01, 0x0A, 0x17, 0x1C, 0x2D, 0x26, 0x3B, 0x30, 0x59, 0x52, 0x4F, 0x44, 0x75, 0x7E, 0x63, 0x68,
	0xB1, 0xBA, 0xA7, 0xAC, 0x9D, 0x96, 0x8B, 0x80, 0xE9, 0xE2, 0xFF, 0xF4, 0xC5, 0xCE, 0xD3, 0xD8,
	0x7A, 0x71, 0x6C, 0x67, 0x56, 0x5D, 0x40, 0x4B, 0x22, 0x29, 0x34, 0x3F, 0x0E, 0x05, 0x18, 0x13,
	0xCA, 0xC1, 0xDC, 0xD7, 0xE6, 0xED, 0xF0, 0xFB, 0x92, 0x99, 0x84, 0x8F, 0xBE, 0xB5, 0xA8, 0xA3
};


/// <summary>
/// Brc4 custom encryption algorithm.
/// </summary>
/// <param name="pbKey">encryption key</param>
/// <param name="pbData">data to be encrypted</param>
/// <param name="dwDataLength">Returns the encrypted data size</param>
/// <returns></returns>
BOOL Brc4::EncryptData(PBYTE pbKey, PBYTE pbData, DWORD& dwDataLength)
{
	if (!pbKey || !pbData)
		return false;

	memmove(g_bKey, pbKey, 16);
	// 16字节xorkey + 生成160字节xorkey = 176字节xorkey
	// 每组xorkey为16字节一共有11组xorkey
	InitXorKeyBox();
	int dataIndex = 0;
	dwDataLength = 16 * (dwDataLength / 16 + 1);
	// 每次加密16字节的明文数据
	for (DWORD j = 0; j < dwDataLength; j += 16) {
		int xorKeyIndex = 16;
		// 使用一组16字节xorkey和明文数据进行异或
		MyXor(g_bKey, pbData + dataIndex);
		for (int i = 0; i < 9; i++) {
			// 以数据为box1数组下标替换16字节数据
			replaceBoxData(pbData + dataIndex);
			// 将16字节数据乱序
			ByteOutOfOrder(pbData + dataIndex);
			// 使用box3和box4异或加密
			boxXorData(pbData + dataIndex);
			MyXor(g_bKey + xorKeyIndex, pbData + dataIndex);
			// 下16字节的xorkey
			xorKeyIndex += 16;
		}
		// 以数据为box1数组下标替换16字节数据
		replaceBoxData(pbData + dataIndex);
		// 将16字节数据乱序
		ByteOutOfOrder(pbData + dataIndex);
		// 使用最后一组16字节的xorkey进行异或加密
		MyXor(g_bKey + xorKeyIndex, pbData + dataIndex);
		// 加密接下来16字节的数据
		dataIndex += 16;
	}
	g_replaceIndex = 1;
	return true;
}

/// <summary>
/// Brc4 custom decryption algorithm.
/// </summary>
/// <param name="pbKey">decryption key</param>
/// <param name="pbData">data to be decrypted</param>
/// <param name="dwDataLength">The size of the data to decrypt</param>
/// <returns></returns>
BOOL Brc4::DecryptData(PBYTE pbKey, PBYTE pbData, DWORD dwDataLength)
{
	if (!pbKey || !pbData)
		return false;

	// 16字节xorkey + 生成160字节xorkey = 176字节xorkey
	// 每组xorkey为16字节一共有11组xorkey
	memmove(g_bKey, pbKey, 16);
	InitXorKeyBox();
	int dataIndex = 0;
	for (DWORD j = 0; j < dwDataLength; j += 16) {
		// 解密要从最后一组xorkey开始
		int KeyIndex = 0xA0;
		// 解密反过来首先使用最后16字节xorkeybox异或
		MyXor(g_bKey + KeyIndex, pbData + dataIndex);
		// 将16字节数据乱序
		DeByteOutOfOrder(pbData + dataIndex);
		// 以数据为box数组下标替换16字节数据
		DereplaceBoxData(pbData + dataIndex);
		for (int i = 0; i < 9; i++) {
			KeyIndex -= 0x10;
			MyXor(g_bKey + KeyIndex, pbData + dataIndex);
			DeboxXorData(pbData + dataIndex);
			// 将16字节数据乱序
			DeByteOutOfOrder(pbData + dataIndex);
			// 以数据为box数组下标替换16字节数据
			DereplaceBoxData(pbData + dataIndex);
		}
		MyXor(g_bKey, pbData + dataIndex);
		// 解密下16字节数据
		dataIndex += 16;
	}
	g_replaceIndex = 1;
	return true;
}

/// <summary>
/// Scan all process memory to find unfortunate Context memory to find malicious processes that are sleeping and obfuscating.
/// </summary>
void Brc4::ScanAllProcessMem()
{
	Process process;
	printf("[+] Start Scan All Process Memory...\n");
	// enum all process
	auto allPid = Process::EnumByNameOrPID(0, L"");
	for (auto it = allPid->begin(); it != allPid->end(); ++it)
	{
		// open process handle
		if (NT_SUCCESS(process.Attach(it->pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
		{
			// enum process memory
			auto& memory = process.memory();
			auto vMbi = memory.EnumRegions();
			for (auto i = vMbi.begin(); i != vMbi.end(); ++i)
			{
				void* pBuf = NULL;
				if (i->State != MEM_COMMIT || i->Protect != PAGE_READWRITE ||
					i->RegionSize > 1024 * 1024 * 50 || i->Type != MEM_PRIVATE)
				{
					continue;
				}
				pBuf = malloc(i->RegionSize);
				if (NT_SUCCESS(memory.Read(i->BaseAddress, i->RegionSize, pBuf)))
				{
					FindSuspiciousContext(*it, pBuf, i->RegionSize);
				}
				free(pBuf);
			}
		}
	}
	PrintFindSuspiciousContext();
	printf("[+] End Scaning\n");
}

/// <summary>
/// Extract Badger Core Dll and Badger Config from Brc4 1.2.2 Badger Payload.
/// </summary>
/// <param name="cpFilePath">Badger Payload Path</param>
/// <returns></returns>
BOOL Brc4::Brc4ConfigExtract(const char* cpFilePath)
{
	BOOL bResult = true;
	PBYTE pbFileBuffer = nullptr;
	DWORD dwFileSize = 0;
	std::vector<ptr_t> vptrX64Start, vptrX64Stage, vptrX86Start;
	PatternSearch ps_X64_Badger{ uiPattern_X64_Start };
	PatternSearch ps_X64_Stage{ uiPattern_X64_Stage };

	if (!MReadFile(cpFilePath, pbFileBuffer, dwFileSize))
	{
		CleanupError();
	}
	if (dwFileSize < 0x1000)
	{
		printf("[!] This file may not be a valid Badger Payload\n");
		CleanupError();
	}
	ps_X64_Badger.Search(pbFileBuffer, dwFileSize, vptrX64Start);
	ps_X64_Stage.Search(pbFileBuffer, dwFileSize, vptrX64Stage);
	// dump x64 badger core dll and config
	if (!vptrX64Start.empty() && vptrX64Stage.empty())
	{
		PatternSearch ps_X64_Config_End{ uiPattern_X64_Config_End };
		PatternSearch ps_X64_Core_End{ uiPattern_X64_Core_End };
		ps_X64_Config_End.Search(0x63, pbFileBuffer, dwFileSize, vptrX64Start);
		ps_X64_Core_End.Search(0x63, pbFileBuffer, dwFileSize, vptrX64Start);
		DumpX64BadgerCoreConfig(vptrX64Start);
	}
	// dump x64 stage config
	else if (!vptrX64Start.empty() && !vptrX64Stage.empty())
	{
		PatternSearch ps_X64_Stage_Config_End{ uiPattern_X64_Config_End };
		ps_X64_Stage_Config_End.Search(0x63, pbFileBuffer, dwFileSize, vptrX64Start);
		DumpX64StageConfig(vptrX64Start);
	}
	// dump x86 badger core dll and config
	else if (vptrX64Start.empty() && vptrX64Stage.empty())
	{
		PatternSearch ps_X86_Start{ uiPattern_X86_Start };
		PatternSearch ps_X86_Config_End{ uiPattern_X86_Config_End };
		PatternSearch ps_X86_Core_End{ uiPattern_X86_Core_End };
		ps_X86_Start.Search(pbFileBuffer, dwFileSize, vptrX86Start);
		ps_X86_Config_End.Search(0x63, pbFileBuffer, dwFileSize, vptrX86Start);
		ps_X86_Core_End.Search(0x63, pbFileBuffer, dwFileSize, vptrX86Start);

		if (vptrX86Start.size() == 3)
			DumpX86BadgerCoreConfig(vptrX86Start);
		else if (vptrX86Start.size() == 2)
			DumpX86StageConfig(vptrX86Start);
		else
			printf("[!] This is not a valid Badger Payload\n");
	}
CLEAR_EXIT:
	MVirtualFree(pbFileBuffer);
	return bResult;
}

/// <summary>
/// Print Brc4 Config to Console
/// </summary>
/// <param name="cpFilePath">Brc4 Config Path</param>
/// <returns></returns>
BOOL Brc4::PrintBrc4Config(const char* cpFilePath)
{
	BOOL bResult = true;
	PBYTE pbConfig = nullptr;
	DWORD dwConfigSize = 0, dwConfigType = 0;
	if (!MReadFile(cpFilePath, pbConfig, dwConfigSize))
		return false;
	dwConfigType = GetConfigTypeNumber(pbConfig, dwConfigSize);
	if (dwConfigType != HTTP_DOH_BADGER && dwConfigType != STAGE_BADGER &&
		dwConfigType != TCP_BADGER && dwConfigType != SMB_BADGER)
	{
		printf("[!] This may not be a Badger Config\n");
		CleanupError();
	}
	if (dwConfigType == HTTP_DOH_BADGER)
	{
		if (!ParseBrc4HTTPDOHConfig(pbConfig, dwConfigSize))
		{
			CleanupError();
		}
		PrintBrc4ConfigToConsole(HTTP_DOH_BADGER);
	}
	else if (dwConfigType == STAGE_BADGER)
	{
		if (!ParseBrc4StageConfig(pbConfig, dwConfigSize))
		{
			CleanupError();
		}
		PrintBrc4ConfigToConsole(STAGE_BADGER);
	}
	else if (dwConfigType == TCP_BADGER)
	{
		if (!ParseBrc4TcpConfig(pbConfig, dwConfigSize))
		{
			CleanupError();
		}
		PrintBrc4ConfigToConsole(TCP_BADGER);
	}
	else if (dwConfigType == SMB_BADGER)
	{
		if (!ParseBrc4SmbConfig(pbConfig, dwConfigSize))
		{
			CleanupError();
		}
		PrintBrc4ConfigToConsole(SMB_BADGER);
	}

CLEAR_EXIT:
	MVirtualFree(pbConfig);
	return bResult;
}

/// <summary>
/// The specified number of Badgers launched from Badger Config currently only supports HTTP/S Listener.
/// </summary>
/// <param name="lpConfigPath">Badger Config Path</param>
/// <param name="dwCount">The number of Badgers to fake online</param>
/// <returns></returns>
BOOL Brc4::FakeOnlineBrc4Badger(const char* lpConfigPath, DWORD dwCount)
{
	BOOL bResult = true;
	DWORD dwConfigSize = 0, dwDataSize = 0, dwBase64Size = 0;
	PBYTE pbConfig = nullptr, pbOnlinePack = nullptr, pbBase64 = nullptr;
	if (!MReadFile(lpConfigPath, pbConfig, dwConfigSize))
		return false;
	if (dwConfigSize < 63)
	{
		printf("[!] This file may not be HTTP/S Badger Config\n");
		MVirtualFree(pbConfig);
		return false;
	}
	if (!ParseBrc4HTTPDOHConfig(pbConfig, dwConfigSize))
	{
		MVirtualFree(pbConfig);
		return false;
	}
	auto it = vBrc4Config.begin();
	auto brc4Config = it->get();
	if (!brc4Config->vDnsHosts.empty())
	{
		printf("[!] This Badger Config is DOH currently only supports HTTP/S Config\n");
		CleanupError();
	}
	do
	{
		pbOnlinePack = MVirtualAlloc(0x200, PAGE_READWRITE);
		if (!pbOnlinePack)
			break;
		RandomOnlinePack(pbOnlinePack);
		dwDataSize = strlen((char*)pbOnlinePack);
		EncryptData((PBYTE)brc4Config->encKey.c_str(), pbOnlinePack, dwDataSize);
		pbBase64 = Base64(BASE64_ENCODE, (char*)pbOnlinePack, dwDataSize, dwBase64Size);
		MVirtualFree(pbOnlinePack);
		brc4Config->onlinePack = (char*)pbBase64;
		MVirtualFree(pbBase64);
		if (!SendHTTPReqToC2())
		{
			printf("[!] Failed Online Fake Badger\n");
			CleanupError();
		}
	} while (--dwCount);
	printf("[+] Sucess Online All Fake Badger...\n");

CLEAR_EXIT:
	MVirtualFree(pbConfig);
	return bResult;
}

/// <summary>
/// Decrypt the base64-encoded Brc4 custom encryption algorithm data.
/// </summary>
/// <param name="enckey">Brc4 custom encryption algorithm key</param>
/// <param name="base64">The base64-encoded Brc4 custom encryption algorithm data to be decrypted</param>
/// <returns></returns>
BOOL Brc4::DecryptBase64Brc4Encrypt(char* enckey, char* base64)
{
	if (!enckey || !base64)
		return false;
	
	DWORD dwDecodeLength = 0;
	PBYTE pbBase64Decode = Base64(BASE64_DECODE, base64, strlen(base64), dwDecodeLength);
	if (!pbBase64Decode) 
	{
		printf("[!] Base64 Decode Error\n");
		return false;
	}
	DecryptData((PBYTE)enckey, pbBase64Decode, dwDecodeLength);
	printf("[+] DecryptData：%s\n", pbBase64Decode);
	MVirtualFree(pbBase64Decode);
	return true;
}


void Brc4::InitXorKeyBox()
{
	int keyLength = 16;
	int Keyindex = 0;
	// 取key最后4字节
	memmove(g_bTemp, g_bKey + 0xc, 4);
	// 16字节xorkey + 生成160字节xorkey = 176字节xorkey
	// 每组xorkey为16字节一共有11组xorkey
	while (keyLength < 176) {
		if (!(keyLength & 0xF)) {
			replaceFourByteKey(g_bTemp);
		}
		for (int i = 0; i < 4; i++) {
			g_bKey[keyLength] = g_bTemp[i] ^ g_bKey[Keyindex];
			g_bTemp[i] = g_bKey[keyLength];
			keyLength++;
			Keyindex++;
		}
	}
}

void Brc4::replaceFourByteKey(unsigned char* fourByteKey)
{
	// ror 8
	*(DWORD*)fourByteKey = ROTR32(*(DWORD*)fourByteKey, 8);
	// 第一个字节处理方式
	unsigned char n_byte1 = g_Box1[fourByteKey[0]] ^ g_Box2[g_replaceIndex];
	fourByteKey[0] = n_byte1;
	// box替换下标+1
	g_replaceIndex++;
	// 2到4字节同方式处理，将数据作为box数组下标替换
	for (int i = 1; i < 4; i++) {
		unsigned char n_byte3 = g_Box1[fourByteKey[i]];
		fourByteKey[i] = n_byte3;
	}
}

void Brc4::MyXor(unsigned char* key, unsigned char* data)
{
	for (int i = 0; i < 16; i++) {
		data[i] = data[i] ^ key[i];
	}
}

void Brc4::replaceBoxData(unsigned char* data)
{
	for (size_t i = 0; i < 16; i++) {
		data[i] = g_Box1[data[i]];
	}
}

void Brc4::ByteOutOfOrder(unsigned char* data)
{
	unsigned char ByteOut[16] = { 0 };
	ByteOut[0] = data[0];
	ByteOut[1] = data[5];
	ByteOut[2] = data[10];
	ByteOut[3] = data[15];
	ByteOut[4] = data[4];
	ByteOut[5] = data[9];
	ByteOut[6] = data[14];
	ByteOut[7] = data[3];
	ByteOut[8] = data[8];
	ByteOut[9] = data[13];
	ByteOut[10] = data[2];
	ByteOut[11] = data[7];
	ByteOut[12] = data[12];
	ByteOut[13] = data[1];
	ByteOut[14] = data[6];
	ByteOut[15] = data[11];
	memmove(data, ByteOut, 16);
}

void Brc4::boxXorData(unsigned char* data)
{
	unsigned char n_TempChang[16] = { 0 };
	// 第1个字节
	unsigned char temp = data[2] ^ data[3];
	temp = temp ^ g_box3[data[0]];
	temp = temp ^ g_box4[data[1]];
	n_TempChang[0] = temp;
	// 第2个字节
	temp = data[0] ^ data[3];
	temp = temp ^ g_box3[data[1]];
	temp = temp ^ g_box4[data[2]];
	n_TempChang[1] = temp;
	// 第3个字节
	temp = data[0] ^ data[1];
	temp = temp ^ g_box3[data[2]];
	temp = temp ^ g_box4[data[3]];
	n_TempChang[2] = temp;
	// 第4个字节
	temp = data[1] ^ data[2];
	temp = temp ^ g_box4[data[0]];
	temp = temp ^ g_box3[data[3]];
	n_TempChang[3] = temp;
	// 第5个字节
	temp = data[6] ^ data[7];
	temp = temp ^ g_box3[data[4]];
	temp = temp ^ g_box4[data[5]];
	n_TempChang[4] = temp;
	// 第6个字节
	temp = data[4] ^ data[7];
	temp = temp ^ g_box3[data[5]];
	temp = temp ^ g_box4[data[6]];
	n_TempChang[5] = temp;
	// 第7个字节
	temp = data[4] ^ data[5];
	temp = temp ^ g_box3[data[6]];
	temp = temp ^ g_box4[data[7]];
	n_TempChang[6] = temp;
	// 第8个字节
	temp = data[5] ^ data[6];
	temp = temp ^ g_box4[data[4]];
	temp = temp ^ g_box3[data[7]];
	n_TempChang[7] = temp;
	// 第9个字节
	temp = data[10] ^ data[11];
	temp = temp ^ g_box3[data[8]];
	temp = temp ^ g_box4[data[9]];
	n_TempChang[8] = temp;
	// 第10个字节
	temp = data[8] ^ data[11];
	temp = temp ^ g_box3[data[9]];
	temp = temp ^ g_box4[data[10]];
	n_TempChang[9] = temp;
	// 第11个字节
	temp = data[8] ^ data[9];
	temp = temp ^ g_box3[data[10]];
	temp = temp ^ g_box4[data[11]];
	n_TempChang[10] = temp;
	// 第12个字节
	temp = data[9] ^ data[10];
	temp = temp ^ g_box4[data[8]];
	temp = temp ^ g_box3[data[11]];
	n_TempChang[11] = temp;
	// 第13个字节
	temp = data[14] ^ data[15];
	temp = temp ^ g_box3[data[12]];
	temp = temp ^ g_box4[data[13]];
	n_TempChang[12] = temp;
	// 第14个字节
	temp = data[12] ^ data[15];
	temp = temp ^ g_box3[data[13]];
	temp = temp ^ g_box4[data[14]];
	n_TempChang[13] = temp;
	// 第15个字节
	temp = data[12] ^ data[13];
	temp = temp ^ g_box3[data[14]];
	temp = temp ^ g_box4[data[15]];
	n_TempChang[14] = temp;
	// 第16个字节
	temp = data[13] ^ data[14];
	temp = temp ^ g_box4[data[12]];
	temp = temp ^ g_box3[data[15]];
	n_TempChang[15] = temp;
	memmove(data, n_TempChang, 16);
}

void Brc4::DeByteOutOfOrder(unsigned char* data)
{
	unsigned char ByteOut[16] = { 0 };
	ByteOut[0] = data[0];
	ByteOut[1] = data[13];
	ByteOut[2] = data[10];
	ByteOut[3] = data[7];
	ByteOut[4] = data[4];
	ByteOut[5] = data[1];
	ByteOut[6] = data[14];
	ByteOut[7] = data[11];
	ByteOut[8] = data[8];
	ByteOut[9] = data[5];
	ByteOut[10] = data[2];
	ByteOut[11] = data[15];
	ByteOut[12] = data[12];
	ByteOut[13] = data[9];
	ByteOut[14] = data[6];
	ByteOut[15] = data[3];
	memmove(data, ByteOut, 16);
}

void Brc4::DereplaceBoxData(unsigned char* data)
{
	for (size_t i = 0; i < 16; i++) {
		data[i] = g_DereplaceFourKeyBox[data[i]];
	}
}

void Brc4::DeboxXorData(unsigned char* data)
{
	unsigned char n_TempChang[16] = { 0 };
	// 第1个字节
	unsigned char temp = g_DeBox1[data[0]];
	temp = temp ^ g_DeBox4[data[1]];
	temp = temp ^ g_DeBox2[data[2]];
	temp = temp ^ g_DeBox3[data[3]];
	n_TempChang[0] = temp;
	// 第2个字节
	temp = g_DeBox3[data[0]];
	temp = temp ^ g_DeBox1[data[1]];
	temp = temp ^ g_DeBox4[data[2]];
	temp = temp ^ g_DeBox2[data[3]];
	n_TempChang[1] = temp;
	// 第3个字节
	temp = g_DeBox2[data[0]];
	temp = temp ^ g_DeBox3[data[1]];
	temp = temp ^ g_DeBox1[data[2]];
	temp = temp ^ g_DeBox4[data[3]];
	n_TempChang[2] = temp;
	// 第4个字节
	temp = g_DeBox4[data[0]];
	temp = temp ^ g_DeBox2[data[1]];
	temp = temp ^ g_DeBox3[data[2]];
	temp = temp ^ g_DeBox1[data[3]];
	n_TempChang[3] = temp;
	// 第5个字节
	temp = g_DeBox1[data[4]];
	temp = temp ^ g_DeBox4[data[5]];
	temp = temp ^ g_DeBox2[data[6]];
	temp = temp ^ g_DeBox3[data[7]];
	n_TempChang[4] = temp;
	// 第6个字节
	temp = g_DeBox3[data[4]];
	temp = temp ^ g_DeBox1[data[5]];
	temp = temp ^ g_DeBox4[data[6]];
	temp = temp ^ g_DeBox2[data[7]];
	n_TempChang[5] = temp;
	// 第7个字节
	temp = g_DeBox2[data[4]];
	temp = temp ^ g_DeBox3[data[5]];
	temp = temp ^ g_DeBox1[data[6]];
	temp = temp ^ g_DeBox4[data[7]];
	n_TempChang[6] = temp;
	// 第8个字节
	temp = g_DeBox4[data[4]];
	temp = temp ^ g_DeBox2[data[5]];
	temp = temp ^ g_DeBox3[data[6]];
	temp = temp ^ g_DeBox1[data[7]];
	n_TempChang[7] = temp;

	// 第9个字节
	temp = g_DeBox1[data[8]];
	temp = temp ^ g_DeBox4[data[9]];
	temp = temp ^ g_DeBox2[data[10]];
	temp = temp ^ g_DeBox3[data[11]];
	n_TempChang[8] = temp;
	// 第10个字节
	temp = g_DeBox3[data[8]];
	temp = temp ^ g_DeBox1[data[9]];
	temp = temp ^ g_DeBox4[data[10]];
	temp = temp ^ g_DeBox2[data[11]];
	n_TempChang[9] = temp;
	// 第11个字节
	temp = g_DeBox2[data[8]];
	temp = temp ^ g_DeBox3[data[9]];
	temp = temp ^ g_DeBox1[data[10]];
	temp = temp ^ g_DeBox4[data[11]];
	n_TempChang[10] = temp;
	// 第12个字节
	temp = g_DeBox4[data[8]];
	temp = temp ^ g_DeBox2[data[9]];
	temp = temp ^ g_DeBox3[data[10]];
	temp = temp ^ g_DeBox1[data[11]];
	n_TempChang[11] = temp;

	// 第13个字节
	temp = g_DeBox1[data[12]];
	temp = temp ^ g_DeBox4[data[13]];
	temp = temp ^ g_DeBox2[data[14]];
	temp = temp ^ g_DeBox3[data[15]];
	n_TempChang[12] = temp;
	// 第14个字节
	temp = g_DeBox3[data[12]];
	temp = temp ^ g_DeBox1[data[13]];
	temp = temp ^ g_DeBox4[data[14]];
	temp = temp ^ g_DeBox2[data[15]];
	n_TempChang[13] = temp;
	// 第15个字节
	temp = g_DeBox2[data[12]];
	temp = temp ^ g_DeBox3[data[13]];
	temp = temp ^ g_DeBox1[data[14]];
	temp = temp ^ g_DeBox4[data[15]];
	n_TempChang[14] = temp;
	// 第16个字节
	temp = g_DeBox4[data[12]];
	temp = temp ^ g_DeBox2[data[13]];
	unsigned char temp2 = g_DeBox3[data[14]];
	unsigned char temp3 = g_DeBox1[data[15]];
	temp = temp ^ temp2 ^ temp3;
	n_TempChang[15] = temp;
	memmove(data, n_TempChang, 16);
}


/// <summary>
/// Dump Badger Core Dll and Badger Config of x64 arch.
/// </summary>
/// <param name="vptr"></param>
/// <returns></returns>
BOOL Brc4::DumpX64BadgerCoreConfig(std::vector<ptr_t>& vptr)
{
	BOOL bResult = true;
	DWORD dwDecodeLength = 0, dwConfigSize = 0, dwCoreSize = 0, dwMoveSize = 0;
	size_t j = 0, k = 0, l = 0;
	BYTE pbCoreRc4Key[8] = { 0 }, pbConfigRc4Key[8] = { 0 };
	ptr_t ptrStart = vptr[0], ptrConfigEnd = vptr[1], ptrConfigStart = NULL, ptrCoreEnd = vptr[2];
	PBYTE pbBadgerCore = nullptr, pbBadgerCoreEnd = nullptr, pbConfig = nullptr, pbConfigEnd = nullptr, pbBase64Decode = nullptr;
	std::vector<ptr_t> vptrRaxRdi, vptrR8R15, vptrMovEax;
	PatternSearch ps_X64_RAX_RDI{ uiPattern_X64_RAX_RDI };
	PatternSearch ps_X64_R8_R15{ uiPattern_X64_R8_R15 };
	PatternSearch ps_X64_MOV_EAX{uiPattern_X64_MOV_EAX };
	ptr_t ptrCoreStart = ptrConfigEnd + uiPattern_X64_Config_End.size();
	ptr_t ptrCoreWrite = ptrCoreStart;

	// get badger config size
	dwConfigSize = *(DWORD*)(ptrConfigEnd + 4);
	// get badger core size
	dwCoreSize = *(DWORD*)(ptrCoreEnd + 4);
	
	pbBadgerCore = MVirtualAlloc(dwCoreSize, PAGE_READWRITE);
	if (!pbBadgerCore)
		return false;
	pbConfig = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
	if (!pbConfig)
		return false;

	pbBadgerCoreEnd = pbBadgerCore + dwCoreSize - 8;

	// get badger core dll
	for (size_t i = 0; i < ptrCoreEnd - ptrCoreStart;)
	{
		if (ps_X64_RAX_RDI.Search(0x63, (PBYTE)ptrCoreWrite, uiPattern_X64_RAX_RDI.size(), vptrRaxRdi) > j)
		{
			auto ptrRaxData = vptrRaxRdi[j];
			ptrRaxData += 2;
			memmove(pbBadgerCoreEnd, (const void*)ptrRaxData, 8);
			i += uiPattern_X64_RAX_RDI.size();
			ptrCoreWrite += uiPattern_X64_RAX_RDI.size();
			j++;
		}
		else if (ps_X64_R8_R15.Search(0x63, (PBYTE)ptrCoreWrite, uiPattern_X64_R8_R15.size(), vptrR8R15) > k)
		{
			auto ptrR8Data = vptrR8R15[k];
			ptrR8Data += 2;
			memmove(pbBadgerCoreEnd, (const void*)ptrR8Data, 8);
			i += uiPattern_X64_R8_R15.size();
			ptrCoreWrite += uiPattern_X64_R8_R15.size();
			k++;
		}
		pbBadgerCoreEnd -= 8;
	}
	vptrRaxRdi.clear();
	vptrR8R15.clear();
	j = k = 0;

	// get badger coer dll rc4 key
	memmove(pbCoreRc4Key, pbBadgerCore + dwCoreSize - 8, RC4_KEY_LENGTH);
	// rc4 decrypt badger core dll
	Rc4(pbBadgerCore, dwCoreSize, pbCoreRc4Key);
	// fix Dos Singature
	((PIMAGE_DOS_HEADER)pbBadgerCore)->e_magic = IMAGE_DOS_SIGNATURE;
	if (!MWriteFile("X64_Badger_Core.dll", pbBadgerCore, dwCoreSize))
	{
		printf("[!] Write X64 Badger Core dll Error\n");
		CleanupError();
	}
	printf("[+] Dump X64 Badger Core Dll Sucess\n");

	// config start
	ptrConfigStart = ptrStart += uiPattern_X64_Start.size();

	// Confirm badger config data size
	if (*(BYTE*)ptrStart == 0xb8)
	{
		for (size_t i = 0, j = 1; i < 4; i++)
		{
			if (*(BYTE*)(ptrStart + j) != 0x00)
				++dwMoveSize;
			++j;
		}
		pbConfigEnd = pbConfig + dwConfigSize - dwMoveSize;
	}
	else
	{
		for (size_t i = 0, j = 2; i < 8; i++)
		{
			if (*(BYTE*)(ptrStart + j) != 0x00)
				++dwMoveSize;
			++j;
		}
		pbConfigEnd = pbConfig + dwConfigSize - dwMoveSize;
	}
		
	// get badger config data
	for (size_t i = 0; i < ptrConfigEnd - ptrStart;)
	{
		if (ps_X64_RAX_RDI.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X64_RAX_RDI.size(), vptrRaxRdi) > j)
		{
			auto ptrRaxData = vptrRaxRdi[j];
			ptrRaxData += 2;
			memmove(pbConfigEnd, (const void*)ptrRaxData, 8);
			i += uiPattern_X64_RAX_RDI.size();
			ptrConfigStart += uiPattern_X64_RAX_RDI.size();
			j++;
		}
		else if (ps_X64_R8_R15.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X64_R8_R15.size(), vptrR8R15) > k)
		{
			auto ptrR8Data = vptrR8R15[k];
			ptrR8Data += 2;
			memmove(pbConfigEnd, (const void*)ptrR8Data, 8);
			i += uiPattern_X64_R8_R15.size();
			ptrConfigStart += uiPattern_X64_R8_R15.size();
			k++;
		}
		else if (ps_X64_MOV_EAX.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X64_MOV_EAX.size(), vptrMovEax) > l)
		{
			auto ptrMovEax = vptrMovEax[l];
			ptrMovEax += 1;
			memmove(pbConfigEnd, (const void*)ptrMovEax, 4);
			i += uiPattern_X64_MOV_EAX.size();
			ptrConfigStart += uiPattern_X64_MOV_EAX.size();
			l++;
		}
		pbConfigEnd -= 8;
	}
	// base64 decode badger config
	pbBase64Decode = Base64(BASE64_DECODE, (char*)pbConfig, strlen((char*)pbConfig), dwDecodeLength);
	if (!pbBase64Decode) {
		printf("[!] Base64 Decode Error\n");
		CleanupError();
	}
	// get badger config rc4 key
	memmove(pbConfigRc4Key, pbBadgerCore + dwCoreSize - 16, RC4_KEY_LENGTH);
	// rc4 decrypt config
	Rc4(pbBase64Decode, dwDecodeLength, pbConfigRc4Key);
	if (!MWriteFile("X64_Badger_Core_Dll.config", pbBase64Decode, dwDecodeLength))
	{
		printf("Write X64 Badger Config Error\n");
		CleanupError();
	}
	printf("[+] Dump X64 Badger Config Sucess\n");

CLEAR_EXIT:
	MVirtualFree(pbBadgerCore);
	MVirtualFree(pbConfig);
	MVirtualFree(pbBase64Decode);
	return bResult;
}

/// <summary>
/// Dump stage config of x64 arch.
/// </summary>
/// <param name="vptr"></param>
/// <returns></returns>
BOOL Brc4::DumpX64StageConfig(std::vector<ptr_t>& vptr)
{
	BOOL bResult = true;
	DWORD dwConfigSize = 0, dwMoveSize = 0;
	size_t j = 0, k = 0, l = 0;
	BYTE pbConfigRc4Key[8] = { 0 };
	ptr_t vptrX64Start = vptr[0], vptrConfigEnd = vptr[1];
	ptr_t vptrConfigStart = vptrX64Start += uiPattern_X64_Start.size();
	PBYTE pbStageConfig = nullptr, pbStageConfigEnd = nullptr;
	std::vector<ptr_t> vptrRaxRdi, vptrR8R15, vptrMovEax;
	PatternSearch ps_X64_RAX_RDI{ uiPattern_X64_RAX_RDI };
	PatternSearch ps_X64_R8_R15{ uiPattern_X64_R8_R15 };
	PatternSearch ps_X64_MOV_EAX{ uiPattern_X64_MOV_EAX };
	
	// get badger config size
	dwConfigSize = *(DWORD*)(vptrConfigEnd + 4);
	pbStageConfig = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
	if (!pbStageConfig)
		return false;

	// Confirm badger config data size
	if (*(BYTE*)vptrConfigStart == 0xb8)
	{
		for (size_t i = 0, j = 1; i < 4; i++)
		{
			if (*(BYTE*)(vptrConfigStart + j) != 0x00)
				++dwMoveSize;
			++j;
		}
		pbStageConfigEnd = pbStageConfig + dwConfigSize - dwMoveSize;
	}	
	else
	{
		for (size_t i = 0, j = 2; i < 8; i++)
		{
			if (*(BYTE*)(vptrConfigStart + j) != 0x00)
				++dwMoveSize;
			++j;
		}
		pbStageConfigEnd = pbStageConfig + dwConfigSize - dwMoveSize;
	}
		
	// get badger config
	for (size_t i = 0; i < vptrConfigEnd - vptrX64Start;)
	{
		if (ps_X64_RAX_RDI.Search(0x63, (PBYTE)vptrConfigStart, uiPattern_X64_RAX_RDI.size(), vptrRaxRdi) > j)
		{
			auto ptrRaxData = vptrRaxRdi[j];
			ptrRaxData += 2;
			memmove(pbStageConfigEnd, (const void*)ptrRaxData, 8);
			i += uiPattern_X64_RAX_RDI.size();
			vptrConfigStart += uiPattern_X64_RAX_RDI.size();
			j++;
		}
		else if (ps_X64_R8_R15.Search(0x63, (PBYTE)vptrConfigStart, uiPattern_X64_R8_R15.size(), vptrR8R15) > k)
		{
			auto ptrR8Data = vptrR8R15[k];
			ptrR8Data += 2;
			memmove(pbStageConfigEnd, (const void*)ptrR8Data, 8);
			i += uiPattern_X64_R8_R15.size();
			vptrConfigStart += uiPattern_X64_R8_R15.size();
			k++;
		}
		else if (ps_X64_MOV_EAX.Search(0x63, (PBYTE)vptrConfigStart, uiPattern_X64_MOV_EAX.size(), vptrMovEax) > l)
		{
			auto ptrMovEax = vptrMovEax[l];
			ptrMovEax += 1;
			memmove(pbStageConfigEnd, (const void*)ptrMovEax, 4);
			i += uiPattern_X64_MOV_EAX.size();
			vptrConfigStart += uiPattern_X64_MOV_EAX.size();
			l++;
		}
		pbStageConfigEnd -= 8;
	}

	// get stage config rc4 key
	memmove(pbConfigRc4Key, pbStageConfig + dwConfigSize - 8, RC4_KEY_LENGTH);
	// rc4 decrypt
	if (!Rc4(pbStageConfig, dwConfigSize - RC4_KEY_LENGTH, pbConfigRc4Key))
	{
		printf("[!] Rc4 Decrypt Error\n");
		CleanupError();
	}
	if (!MWriteFile("X64_Stage.config", pbStageConfig, dwConfigSize - RC4_KEY_LENGTH))
	{
		printf("[!] Write X64 Stage Config Error\n");
		CleanupError();
	}
	printf("[+] Dump X64 Stage Config Sucess\n");

CLEAR_EXIT:
	MVirtualFree(pbStageConfig);
	return bResult;
}

/// <summary>
/// Dump Badger Core Dll and Badger Config of x86 arch.
/// </summary>
/// <param name="vptr"></param>
/// <returns></returns>
BOOL Brc4::DumpX86BadgerCoreConfig(std::vector<ptr_t>& vptr)
{
	BOOL bResult = true;
	BYTE pbCoreRc4Key[8] = { 0 }, pbConfigRc4Key[8] = { 0 };
	DWORD dwConfigSize = 0, dwCoreSize = 0, dwDecodeLength = 0, dwMoveSize = 0;
	size_t j = 0, k = 0, l = 0, m = 0, n = 0;
	ptr_t ptrX86Start = vptr[0], ptrConfigEnd = vptr[1], ptrCoreEnd = vptr[2];
	ptr_t ptrConfigStart = ptrX86Start += uiPattern_X86_Start.size();
	ptr_t ptrCoreStart = ptrConfigEnd + uiPattern_X86_Config_End.size();
	PBYTE pbConfig = nullptr, pbConfigEnd = nullptr, pbBadgerCore = nullptr, pbBase64Decode = nullptr, pbCoreEnd = nullptr;
	std::vector<ptr_t> vptrEaxPush, vptrEsiPush, vptrEdiPush, vptrEcxPush, vptrEdxPush;
	PatternSearch psX86_MOV_EAX_PUSH{ uiPattern_X86_MOV_EAX_PUSH };
	PatternSearch psX86_MOV_ESI_PUSH{ uiPattern_X86_MOV_ESI_PUSH };
	PatternSearch psX86_MOV_EDI_PUSH{ uiPattern_X86_MOV_EDI_PUSH };
	PatternSearch psX86_MOV_ECX_PUSH{ uiPattern_X86_MOV_ECX_PUSH };
	PatternSearch psX86_MOV_EDX_PUSH{ uiPattern_X86_MOV_EDX_PUSH };

	// get badger config size
	dwConfigSize = *(DWORD*)(ptrConfigEnd + 3);
	// get badger core dll size
	dwCoreSize = *(DWORD*)(ptrCoreEnd + 3);
	pbConfig = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
	if (!pbConfig)
		return false;
	pbBadgerCore = MVirtualAlloc(dwCoreSize, PAGE_READWRITE);
	if (!pbBadgerCore)
		return false;
	
	pbCoreEnd = pbBadgerCore + dwCoreSize - 4;

	// get badger core dll
	for (size_t i = 0; i < ptrCoreEnd - ptrConfigEnd - 8;)
	{
		if (psX86_MOV_EAX_PUSH.Search(0x63, (PBYTE)ptrCoreStart, uiPattern_X86_MOV_EAX_PUSH.size(), vptrEaxPush) > j)
		{
			auto ptrEaxPush = vptrEaxPush[j];
			ptrEaxPush += 1;
			memmove(pbCoreEnd, (const void*)ptrEaxPush, 4);
			i += uiPattern_X86_MOV_EAX_PUSH.size();
			ptrCoreStart += uiPattern_X86_MOV_EAX_PUSH.size();
			j++;
		}
		else if (psX86_MOV_ESI_PUSH.Search(0x63, (PBYTE)ptrCoreStart, uiPattern_X86_MOV_ESI_PUSH.size(), vptrEsiPush) > k)
		{
			auto ptrEsiPush = vptrEsiPush[k];
			ptrEsiPush += 1;
			memmove(pbCoreEnd, (const void*)ptrEsiPush, 4);
			i += uiPattern_X86_MOV_ESI_PUSH.size();
			ptrCoreStart += uiPattern_X86_MOV_ESI_PUSH.size();
			k++;
		}
		else if (psX86_MOV_EDI_PUSH.Search(0x63, (PBYTE)ptrCoreStart, uiPattern_X86_MOV_EDI_PUSH.size(), vptrEdiPush) > l)
		{
			auto ptrEdiPush = vptrEdiPush[l];
			ptrEdiPush += 1;
			memmove(pbCoreEnd, (const void*)ptrEdiPush, 4);
			i += uiPattern_X86_MOV_EDI_PUSH.size();
			ptrCoreStart += uiPattern_X86_MOV_EDI_PUSH.size();
			l++;
		}
		pbCoreEnd -= 4;
	}
	j = k = l = 0;
	vptrEaxPush.clear();
	vptrEsiPush.clear();
	vptrEdiPush.clear();
	// get badger coer dll rc4 key
	memmove(pbCoreRc4Key, pbBadgerCore + dwCoreSize - 8, RC4_KEY_LENGTH);
	// rc4 decrypt badger core dll
	Rc4(pbBadgerCore, dwCoreSize, pbCoreRc4Key);
	// fix Dos Singature
	((PIMAGE_DOS_HEADER)pbBadgerCore)->e_magic = IMAGE_DOS_SIGNATURE;
	if (!MWriteFile("X86_Badger_Core.dll", pbBadgerCore, dwCoreSize))
	{
		printf("[!] Write x86 Badger Core Dll Error\n");
		CleanupError();
	}
	printf("[+] Dump x86 Badger Core Dll Sucess\n");

	for (size_t i = 0, j = 1; i < 4; i++)
	{
		if (*(BYTE*)(ptrConfigStart + j) != 0x00)
			++dwMoveSize;
		++j;
	}

	pbConfigEnd = pbConfig + dwConfigSize - dwMoveSize;

	// get badger config
	for (size_t i = 0; i < ptrConfigEnd - ptrX86Start;)
	{
		if (psX86_MOV_EAX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EAX_PUSH.size(), vptrEaxPush) > j)
		{
			auto ptrEaxPush = vptrEaxPush[j];
			ptrEaxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEaxPush, 4);
			i += uiPattern_X86_MOV_EAX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EAX_PUSH.size();
			j++;
		}
		else if (psX86_MOV_ESI_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_ESI_PUSH.size(), vptrEsiPush) > k)
		{
			auto ptrEsiPush = vptrEsiPush[k];
			ptrEsiPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEsiPush, 4);
			i += uiPattern_X86_MOV_ESI_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_ESI_PUSH.size();
			k++;
		}
		else if (psX86_MOV_EDI_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EDI_PUSH.size(), vptrEdiPush) > l)
		{
			auto ptrEdiPush = vptrEdiPush[l];
			ptrEdiPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEdiPush, 4);
			i += uiPattern_X86_MOV_EDI_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EDI_PUSH.size();
			l++;
		}
		else if (psX86_MOV_ECX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_ECX_PUSH.size(), vptrEcxPush) > m)
		{
			auto ptrEcxPush = vptrEcxPush[m];
			ptrEcxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEcxPush, 4);
			i += uiPattern_X86_MOV_ECX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_ECX_PUSH.size();
			m++;
		}
		else if (psX86_MOV_EDX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EDX_PUSH.size(), vptrEdxPush) > n)
		{
			auto ptrEdxPush = vptrEdxPush[n];
			ptrEdxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEdxPush, 4);
			i += uiPattern_X86_MOV_EDX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EDX_PUSH.size();
			n++;
		}
		pbConfigEnd -= 4;
	}
	// base64 decode badger config
	pbBase64Decode = Base64(BASE64_DECODE, (char*)pbConfig, strlen((char*)pbConfig), dwDecodeLength);
	if (!pbBase64Decode) {
		printf("[!] Base64 Decode Error\n");
		CleanupError();
	}
	// get badger config rc4 key
	memmove(pbConfigRc4Key, pbBadgerCore + dwCoreSize - 16, RC4_KEY_LENGTH);
	// rc4 decrypt config
	Rc4(pbBase64Decode, dwDecodeLength, pbConfigRc4Key);
	if (!MWriteFile("X86_Badger_Core_Dll.config", pbBase64Decode, dwDecodeLength))
	{
		printf("[!] Write X86 Badger Config Error\n");
		CleanupError();
	}
	printf("[+] Dump Badger Config Sucess\n");

CLEAR_EXIT:
	MVirtualFree(pbConfig);
	MVirtualFree(pbBadgerCore);
	MVirtualFree(pbBase64Decode);
	return bResult;
}

/// <summary>
/// Dump the Stage Config of the x86 arch.
/// </summary>
/// <param name="vptr"></param>
/// <returns></returns>
BOOL Brc4::DumpX86StageConfig(std::vector<ptr_t>& vptr)
{
	DWORD dwConfigSize = 0, dwMoveSize = 0;
	size_t j = 0, k = 0, l = 0, m = 0, n = 0;
	BYTE pbConfigRc4Key[8] = { 0 };
	ptr_t ptrX86Start = vptr[0], ptrConfigEnd = vptr[1];
	ptr_t ptrConfigStart = ptrX86Start += uiPattern_X86_Start.size();
	PBYTE pbConfig = nullptr, pbConfigEnd = nullptr;
	std::vector<ptr_t> vptrEaxPush, vptrEsiPush, vptrEdiPush, vptrEcxPush, vptrEdxPush;
	PatternSearch psX86_MOV_EAX_PUSH{ uiPattern_X86_MOV_EAX_PUSH };
	PatternSearch psX86_MOV_ESI_PUSH{ uiPattern_X86_MOV_ESI_PUSH };
	PatternSearch psX86_MOV_EDI_PUSH{ uiPattern_X86_MOV_EDI_PUSH };
	PatternSearch psX86_MOV_ECX_PUSH{ uiPattern_X86_MOV_ECX_PUSH };
	PatternSearch psX86_MOV_EDX_PUSH{ uiPattern_X86_MOV_EDX_PUSH };

	// get badger config size
	dwConfigSize = *(DWORD*)(ptrConfigEnd + 3);
	pbConfig = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
	if (!pbConfig)
		return false;

	for (size_t i = 0, j = 1; i < 4; i++)
	{
		if (*(BYTE*)(ptrConfigStart + j) != 0x00)
			++dwMoveSize;
		++j;
	}
	pbConfigEnd = pbConfig + dwConfigSize - dwMoveSize;

	// get badger config
	for (size_t i = 0; i < ptrConfigEnd - ptrX86Start;)
	{
		if (psX86_MOV_EAX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EAX_PUSH.size(), vptrEaxPush) > j)
		{
			auto ptrEaxPush = vptrEaxPush[j];
			ptrEaxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEaxPush, 4);
			i += uiPattern_X86_MOV_EAX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EAX_PUSH.size();
			j++;
		}
		else if (psX86_MOV_ESI_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_ESI_PUSH.size(), vptrEsiPush) > k)
		{
			auto ptrEsiPush = vptrEsiPush[k];
			ptrEsiPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEsiPush, 4);
			i += uiPattern_X86_MOV_ESI_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_ESI_PUSH.size();
			k++;
		}
		else if (psX86_MOV_EDI_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EDI_PUSH.size(), vptrEdiPush) > l)
		{
			auto ptrEdiPush = vptrEdiPush[l];
			ptrEdiPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEdiPush, 4);
			i += uiPattern_X86_MOV_EDI_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EDI_PUSH.size();
			l++;
		}
		else if (psX86_MOV_ECX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_ECX_PUSH.size(), vptrEcxPush) > m)
		{
			auto ptrEcxPush = vptrEcxPush[m];
			ptrEcxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEcxPush, 4);
			i += uiPattern_X86_MOV_ECX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_ECX_PUSH.size();
			m++;
		}
		else if (psX86_MOV_EDX_PUSH.Search(0x63, (PBYTE)ptrConfigStart, uiPattern_X86_MOV_EDX_PUSH.size(), vptrEdxPush) > n)
		{
			auto ptrEdxPush = vptrEdxPush[n];
			ptrEdxPush += 1;
			memmove(pbConfigEnd, (const void*)ptrEdxPush, 4);
			i += uiPattern_X86_MOV_EDX_PUSH.size();
			ptrConfigStart += uiPattern_X86_MOV_EDX_PUSH.size();
			n++;
		}
		pbConfigEnd -= 4;
	}
	// get stage config rc4 key
	memmove(pbConfigRc4Key, pbConfig + dwConfigSize - 8, RC4_KEY_LENGTH);
	// rc4 decrypt
	Rc4(pbConfig, dwConfigSize - RC4_KEY_LENGTH, pbConfigRc4Key);
	if (!MWriteFile("X86_Stage.config", pbConfig, dwConfigSize - RC4_KEY_LENGTH))
	{
		printf("[!] Write X86 Stage Config Error\n");
	}
	printf("[+] Dump X86 Stage Config Sucess\n");

	MVirtualFree(pbConfig);
	return true;
}

/// <summary>
/// Get Badger Config type
/// </summary>
/// <param name="pbConfig">Badger Config data</param>
/// <param name="dwConfigSize">Badger Config Size</param>
/// <returns>Badger Config Type</returns>
DWORD Brc4::GetConfigTypeNumber(PBYTE pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig || *(pbConfig + dwConfigSize - 1) != '|')
		return 0;
	DWORD dwTypeNumber = 0;
	while (*pbConfig != '\0')
	{
		if (*pbConfig == '|')
			dwTypeNumber++;
		pbConfig++;
	}
	return dwTypeNumber;
}

/// <summary>
/// check multiple parameters
/// </summary>
/// <param name="pbConfig"></param>
/// <returns></returns>
DWORD Brc4::CheckMultipleFields(PBYTE pbConfig)
{
	if (!pbConfig)
		return 0;
	DWORD dwCount = 0;
	while (*pbConfig != '\0' && *pbConfig != '|')
	{
		if (*pbConfig == ',')
			dwCount++;
		pbConfig++;
	}
	return dwCount;
}

/// <summary>
/// Parse Badger Config fields with multiple parameters
/// </summary>
/// <param name="pbConfig"></param>
/// <param name="dwConfigSize"></param>
/// <param name="vString"></param>
/// <returns></returns>
BOOL Brc4::ParseMultipleConfigFields(PBYTE& pbConfig, DWORD dwConfigSize, std::vector<std::string>& vString)
{
	if (!pbConfig)
		return false;

	DWORD dwCount = 0;
	PBYTE pbFields = nullptr;
	dwCount = CheckMultipleFields(pbConfig);
	if (!dwCount)
	{
		pbFields = ParseConfigFields(pbConfig, dwConfigSize);
		if (!pbFields)
		{
			return false;
		}
		vString.push_back((char*)pbFields);
		return true;
	}
	for (DWORD i = 0; i <= dwCount; i++)
	{
		pbFields = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
		if (!pbFields)
			return false;
		for (DWORD j = 0; *pbConfig !=',' && *pbConfig!='|'; j++)
		{
			pbFields[j] = *pbConfig;
			pbConfig++;
		}
		vString.push_back((char*)pbFields);
		MVirtualFree(pbFields);
		// skip , or |
		pbConfig++;
	}
	return true;
}

/// <summary>
/// Parse the Brc4 Config field
/// </summary>
/// <param name="pbConfig"></param>
/// <param name="dwConfigSize"></param>
/// <returns></returns>
PBYTE Brc4::ParseConfigFields(PBYTE& pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig)
		return nullptr;
	DWORD dwCount;
	PBYTE pbFields = MVirtualAlloc(dwConfigSize, PAGE_READWRITE);
	if (!pbFields)
		return nullptr;
	for (dwCount = 0; *pbConfig != '|'; dwCount++)
	{
		pbFields[dwCount] = *pbConfig;
		pbConfig++;
	}
	// skip |
	pbConfig++;
	if (!dwCount)
	{
		MVirtualFree(pbFields);
		return nullptr;
	}
	return pbFields;
}

/// <summary>
/// Convert Ascii string to hexadecimal number
/// </summary>
/// <param name="pbConfig"></param>
/// <returns>hexadecimal Number</returns>
DWORD Brc4::AsciiToHex(PBYTE pbConfig)
{
	if (!pbConfig)
		return 0;
	char chr = 0;
	DWORD hex = 0, temp = 0;
	while (1) {
		chr = *pbConfig;
		if (*pbConfig != ' ')
			break;
		++pbConfig;
	}
	if (chr == '-') {
		++pbConfig;
	}
	else {
		if (chr == '+')
			++pbConfig;
	}

	while (1) {
		temp = *pbConfig - '0';
		if (temp > 9)
			break;
		hex = hex * 10;
		pbConfig++;
		hex += temp;
	}
	return hex;
}

/// <summary>
/// Parse Brc4 Smb Config
/// </summary>
/// <param name="pbConfig"></param>
/// <param name="dwConfigSize"></param>
/// <returns></returns>
BOOL Brc4::ParseBrc4SmbConfig(PBYTE pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig)
		return false;
	PBYTE pbTempBuff = nullptr;
	auto uBrc4Config = std::make_unique<Brc4Config>();
	// 1.SleepObfuscation：0=APC,1=Poling-0,2=Poling-1
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->sleepObfuscation = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 2.pipe name
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->pipeName = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 3.AuthKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->authKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 4.EncKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->encKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}

	vBrc4Config.push_back(std::move(uBrc4Config));
	return true;
}

/// <summary>
/// Parse Brc4 Tcp Config
/// </summary>
/// <param name="pbConfig"></param>
/// <param name="dwConfigSize"></param>
/// <returns></returns>
BOOL Brc4::ParseBrc4TcpConfig(PBYTE pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig)
		return false;
	PBYTE pbTempBuff = nullptr;
	auto uBrc4Config = std::make_unique<Brc4Config>();
	// 1.SleepObfuscation：0=APC,1=Poling-0,2=Poling-1
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->sleepObfuscation = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 2.host
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vHost);
	// 3.port
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->port = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 4.AuthKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->authKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 5.EncKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->encKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}

	vBrc4Config.push_back(std::move(uBrc4Config));
	return true;
}

/// <summary>
/// Parse Brc4 Stage Config
/// </summary>
/// <param name="pbConfig"></param>
/// <param name="dwConfigSize"></param>
/// <returns></returns>
BOOL Brc4::ParseBrc4StageConfig(PBYTE pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig)
		return false;
	DWORD dwDecodeLength = 0;
	PBYTE pbTempBuff = nullptr;
	auto uBrc4Config = std::make_unique<Brc4Config>();
	// 1.Proxy
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->proxy = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 2.prepend
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->prepended = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);

	}
	// 3.append
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->appended = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 4.ssl
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->ssl = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 5.host
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vHost);
	// 6.port
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->port = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 7.User-Agent
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->userAgent = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 8.AuthKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->authKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 9.EncKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->encKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 10.URIs
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vURIs);
	// 11.extra_headers
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vExtraHeaders);

	vBrc4Config.push_back(std::move(uBrc4Config));

	return true;
}

/// <summary>
/// Parse Brc4 HTTP/S or DOH Config
/// </summary>
/// <param name="pbConfig">Config Data Buffer</param>
/// <param name="dwConfigSize">Config Data Size</param>
/// <returns></returns>
BOOL Brc4::ParseBrc4HTTPDOHConfig(PBYTE pbConfig, DWORD dwConfigSize)
{
	if (!pbConfig)
		return false;
	DWORD dwConfigType = 0, dwDecodeLength = 0;
	PBYTE pbTempBuff = nullptr;
	dwConfigType = GetConfigTypeNumber(pbConfig, dwConfigSize);
	if (dwConfigType != HTTP_DOH_BADGER)
	{
		printf("[!] Please check your configuration file, currently only HTTP/S Badger configuration files are supported\n");
		return false;
	}
	auto uBrc4Config = std::make_unique<Brc4Config>();
	// 1.SleepObfuscation：0=APC,1=Poling-0,2=Poling-1
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->sleepObfuscation = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 2.Sleep Time
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->sleepTime = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 3.Jitter Time
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->jitterTime = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 4.Proxy
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->proxy = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 5.dns hosts
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vDnsHosts);
	// 6.Check-in A Record
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->checkInARecord = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 7.idleA A Record
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->idleARecord = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 8.Prepended Post Data
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		pbTempBuff = Base64(BASE64_DECODE, (char*)pbTempBuff, strlen((char*)pbTempBuff), dwDecodeLength);
		if (pbTempBuff)
		{
			uBrc4Config->prepended = (char*)pbTempBuff;
			MVirtualFree(pbTempBuff);
		}
	}
	// 9.Appended Post Data
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		pbTempBuff = Base64(BASE64_DECODE, (char*)pbTempBuff, strlen((char*)pbTempBuff), dwDecodeLength);
		if (pbTempBuff)
		{
			uBrc4Config->appended = (char*)pbTempBuff;
			MVirtualFree(pbTempBuff);
		}
	}
	// 10.Die if C2 Offline
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->dieIfC2Offline = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 11.SSL
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->ssl = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 12.Host
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vHost);
	// 13.Port
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->port = AsciiToHex(pbTempBuff);
		MVirtualFree(pbTempBuff);
	}
	// 14.UserAgent
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->userAgent = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 15.AuthKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->authKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 16.EncKey
	pbTempBuff = ParseConfigFields(pbConfig, dwConfigSize);
	if (pbTempBuff)
	{
		uBrc4Config->encKey = (char*)pbTempBuff;
		MVirtualFree(pbTempBuff);
	}
	// 17.URIS
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vURIs);
	// 18.extra_headers
	ParseMultipleConfigFields(pbConfig, dwConfigSize, uBrc4Config->vExtraHeaders);

	vBrc4Config.push_back(std::move(uBrc4Config));
	return true;
}

/// <summary>
/// Parse and print Brc4 Config to the console
/// </summary>
/// <param name="dwConfigType">Brc4 Config Type</param>
void Brc4::PrintBrc4ConfigToConsole(DWORD dwConfigType)
{
	auto it = vBrc4Config.begin();
	auto brc4Config = it->get();
	static const char* cpObfSleep[3] = { "APC","Poling-0","Poling-1" };
	// 2.Sleep Time
	if (dwConfigType == HTTP_DOH_BADGER)
	{
		printf("------------------------------------HTTP/S Or DOH Config------------------------------------\n\n");
		// 1.ObfSleep
		printf("ObfSleep：%s\n\n", cpObfSleep[brc4Config->sleepObfuscation]);
		// 2.Sleep Time
		printf("Sleep Time：%d\n\n", brc4Config->sleepTime);
		// 3.Jitter Time
		printf("Jitter Time：%d\n\n", brc4Config->jitterTime);
		// 4.proxy
		if (!brc4Config->proxy.empty())
			printf("Proxy：%s\n\n", brc4Config->proxy.c_str());
		// 5.DnsHosts
		if (!brc4Config->vDnsHosts.empty())
		{
			printf("Dns Hosts：");
			for (auto it = brc4Config->vDnsHosts.begin(); it != brc4Config->vDnsHosts.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 6.checkInARecord
		if (!brc4Config->checkInARecord.empty())
		{
			printf("Check-in A Record：%s\n\n", brc4Config->checkInARecord.c_str());
		}
		// 7.idleARecord
		if (!brc4Config->idleARecord.empty())
		{
			printf("idleA A Record：%s\n\n", brc4Config->idleARecord.c_str());
		}
		// 8.prepended
		if (!brc4Config->prepended.empty())
		{
			printf("Prepended Post Data：%s\n\n", brc4Config->prepended.c_str());
		}
		// 9.appended
		if (!brc4Config->appended.empty())
		{
			printf("Appended Post Data：%s\n\n", brc4Config->appended.c_str());
		}
		// 10.Die if C2 Offline
		printf("Die if C2 Offline：%s\n\n", brc4Config->dieIfC2Offline ? "true" : "false");
		// 11.SSL
		printf("SSL：%s\n\n", brc4Config->ssl ? "true" : "false");
		// 12.Host
		if (!brc4Config->vHost.empty())
		{
			printf("Host：");
			for (auto it = brc4Config->vHost.begin(); it != brc4Config->vHost.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 13.Port
		printf("Port：%d\n\n", brc4Config->port);
		// 14.User-Agent
		if (!brc4Config->userAgent.empty())
		{
			printf("User-Agent：%s\n\n", brc4Config->userAgent.c_str());
		}
		// 15.AuthKey
		if (!brc4Config->authKey.empty())
		{
			printf("AuthKey：%s\n\n", brc4Config->authKey.c_str());
		}
		// 16.EncKey
		if (!brc4Config->encKey.empty())
		{
			printf("EncKey：%s\n\n", brc4Config->encKey.c_str());
		}
		// 17.URIs
		if (!brc4Config->vURIs.empty())
		{
			printf("URIs：");
			for (auto it = brc4Config->vURIs.begin(); it != brc4Config->vURIs.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 18.ExtraHeaders
		if (!brc4Config->vExtraHeaders.empty())
		{
			printf("Extra Headers：");
			for (auto it = brc4Config->vExtraHeaders.begin(); it != brc4Config->vExtraHeaders.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
	}
	else if (dwConfigType == STAGE_BADGER)
	{
		printf("------------------------------------stage badger config------------------------------------\n\n");
		// 1.Proxy
		if (!brc4Config->proxy.empty())
		{
			printf("Proxy：%s\n\n", brc4Config->proxy.c_str());
		}
		// 2.prepend
		if (!brc4Config->prepended.empty())
		{
			printf("Prepended Post Data：%s\n\n", brc4Config->prepended.c_str());
		}
		// 3.append
		if (!brc4Config->appended.empty())
		{
			printf("Appended Post Data：%s\n\n", brc4Config->appended.c_str());
		}
		// 4.ssl
		printf("SSL：%s\n\n", brc4Config->ssl ? "true" : "false");
		// 5.host
		if (!brc4Config->vHost.empty())
		{
			printf("Host：");
			for (auto it = brc4Config->vHost.begin(); it != brc4Config->vHost.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 6.port
		printf("Port：%d\n\n", brc4Config->port);
		// 7.User-Agent
		if (!brc4Config->userAgent.empty())
		{
			printf("User-Agent：%s\n\n", brc4Config->userAgent.c_str());
		}
		// 8.AuthKey
		if (!brc4Config->authKey.empty())
		{
			printf("AuthKey：%s\n\n", brc4Config->authKey.c_str());
		}
		// 9.EncKey
		if (!brc4Config->encKey.empty())
		{
			printf("EncKey：%s\n\n", brc4Config->encKey.c_str());
		}
		// 10.URIs
		if (!brc4Config->vURIs.empty())
		{
			printf("URIs：");
			for (auto it = brc4Config->vURIs.begin(); it != brc4Config->vURIs.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 11.extra_headers
		if (!brc4Config->vExtraHeaders.empty())
		{
			printf("Extra Headers：");
			for (auto it = brc4Config->vExtraHeaders.begin(); it != brc4Config->vExtraHeaders.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
	}
	else if (dwConfigType == SMB_BADGER)
	{
		printf("------------------------------------smb badger config------------------------------------\n\n");
		// 1.SleepObfuscation：0=APC,1=Poling-0,2=Poling-1
		printf("ObfSleep：%s\n\n", cpObfSleep[brc4Config->sleepObfuscation]);
		// 2.pipe name
		if (!brc4Config->pipeName.empty())
		{
			printf("SMB pipe name：%s\n\n", brc4Config->pipeName.c_str());
		}
		// 3.AuthKey
		if (!brc4Config->authKey.empty())
		{
			printf("AuthKey：%s\n\n", brc4Config->authKey.c_str());
		}
		// 4.EncKey
		if (!brc4Config->encKey.empty())
		{
			printf("EncKey：%s\n\n", brc4Config->encKey.c_str());
		}
	}
	else if (dwConfigType == TCP_BADGER)
	{
		printf("------------------------------------tcp badger config------------------------------------\n\n");
		// 1.SleepObfuscation：0=APC,1=Poling-0,2=Poling-1
		printf("ObfSleep：%s\n\n", cpObfSleep[brc4Config->sleepObfuscation]);
		// 2.host
		if (!brc4Config->vHost.empty())
		{
			printf("Host：");
			for (auto it = brc4Config->vHost.begin(); it != brc4Config->vHost.end(); it++)
			{
				printf("%s, ", it->c_str());
			}
			printf("\n\n");
		}
		// 3.port
		printf("Port：%d\n\n", brc4Config->port);
		// 4.AuthKey
		if (!brc4Config->authKey.empty())
		{
			printf("AuthKey：%s\n\n", brc4Config->authKey.c_str());
		}
		// 5.EncKey 
		if (!brc4Config->encKey.empty())
		{
			printf("EncKey：%s\n\n", brc4Config->encKey.c_str());
		}
	}
}

/// <summary>
/// Random Badger online package
/// </summary>
/// <param name="pbOnlinePack"></param>
void Brc4::RandomOnlinePack(PBYTE pbOnlinePack)
{
	if (!pbOnlinePack)
		return;
	LPCSTR auth = "{\"cds\":{\"auth\":\"";
	LPCSTR hname = "\"},\"mtdt\":{\"h_name\":\"";
	LPCSTR wver = "\",\"wver\":\"";
	LPCSTR arch = "\",\"arch\":\"";
	LPCSTR bld = "\",\"bld\":\"";
	LPCSTR pname = "\",\"p_name\":\"";
	LPCSTR uid = "\",\"uid\":\"";
	LPCSTR pid = "\",\"pid\":\"";
	LPCSTR tid = "\",\"tid\":\"";
	LPCSTR end = "\"}}\r\n";

	DWORD ArrRandom = 0;
	static const char* winverArray[4][4] = { {"x64/6.0","x64","7601","win764"}, { "x64/6.0","x64","9600","win864" },{ "x64/10.0","x64","19045","win1064" },{ "x64/10.0","x64","22621","win1164" } };
	static const char* hostNameArray[5] = { {"DESKTOP-HJ5F9NV"},{"DESKTOP-OG3ZJSB" }, {"DESKTOP-KAGW8LQ"}, {"DESKTOP-LE3HO1Z"}, {"DESKTOP-PZAHJW2"} };
	static const char* processArray[4] = { {"QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlAAA="},
		{"QwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAFIAdQBuAHQAaQBtAGUAQgByAG8AawBlAHIALgBlAHgAZQA="},
		{"KiBDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAcwB2AGMAaABvAHMAdAAuAGUAeABlAA=="},
		{"QwA6AFwAVQBzAGUAcgBzAFwARABlAGYAYQB1AGwAdABcAEEAcABwAEQAYQB0AGEAXABsAG8AYQBkAC4AZQB4AGUA"} };

	std::random_device rd;
	std::mt19937 gen(rd());
	// pid and tid random
	std::uniform_int_distribution<> pidtid(800, 20000);
	std::uniform_int_distribution<> winver(0, 3);
	std::uniform_int_distribution<> hostname(0, 4);
	ArrRandom = winver(gen);
	auto it = vBrc4Config.begin();
	auto brc4Config = it->get();
	sprintf_s((char*)pbOnlinePack, 0x200, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d%s%d%s", auth, brc4Config->authKey.c_str(), hname, hostNameArray[hostname(gen)], wver, winverArray[ArrRandom][0], arch, winverArray[ArrRandom][1], bld, winverArray[ArrRandom][2], pname, processArray[ArrRandom], uid, winverArray[ArrRandom][3], pid, pidtid(gen), tid, pidtid(gen), end);
}

/// <summary>
/// Fake online HTTP/S Badger
/// </summary>
/// <returns></returns>
BOOL Brc4::SendHTTPReqToC2()
{
	BOOL bResult = true;
	DWORD dwAppendedSize = 0, dwOptionBuffer = 0x1100;
	PBYTE pbAppended = nullptr;
	HINTERNET hInterNet = NULL, hConnect = NULL, hReq = NULL;
	auto it = vBrc4Config.begin();
	auto brc4Config = it->get();
	std::random_device rd;
	std::mt19937 gen(rd());
	// random URIs and Host
	std::uniform_int_distribution<> randURIs(0, brc4Config->vURIs.size() - 1);
	std::uniform_int_distribution<> randHost(0, brc4Config->vHost.size() - 1);

	hInterNet = InternetOpenA(
		brc4Config->userAgent.c_str(), !brc4Config->proxy.empty() ? INTERNET_OPEN_TYPE_PROXY : 0, 
		!brc4Config->proxy.empty() ? brc4Config->proxy.c_str() : 0, 0, 0);
	if (!hInterNet) 
	{
		PrintErrorMsg("InternetOpenA");
	}

	hConnect = InternetConnectA(
		hInterNet, brc4Config->vHost[randHost(gen)].c_str(), brc4Config->port, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) 
	{
		PrintErrorMsg("InternetConnectA");
		CleanupError();
	}

	hReq = HttpOpenRequestA(
		hConnect, "POST", brc4Config->vURIs[randURIs(gen)].c_str(), 0, 0, 0, brc4Config->ssl ? 0x84880300 : 0x84080300, 0);
	if (!hReq) 
	{
		PrintErrorMsg("HttpOpenRequestA");
		CleanupError();
	}

	if (!InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwOptionBuffer, 4)) 
	{
		PrintErrorMsg("InternetSetOptionA");
		CleanupError();
	}

	if (!brc4Config->vExtraHeaders.empty())
	{
		for (auto it = brc4Config->vExtraHeaders.begin(); it != brc4Config->vExtraHeaders.end(); ++it)
		{
			if (!HttpAddRequestHeadersA(hReq, it->c_str(), -1L, HTTP_ADDREQ_FLAG_ADD))
			{
				PrintErrorMsg("HttpAddRequestHeadersA");
				CleanupError();
			}
		}
	}

	if (!brc4Config->appended.empty() && !brc4Config->prepended.empty())
	{
		dwAppendedSize = brc4Config->appended.size() + brc4Config->prepended.size() + brc4Config->onlinePack.size() + 1;
		pbAppended = MVirtualAlloc(dwAppendedSize, PAGE_READWRITE);
		if (!pbAppended)
		{
			CleanupError();
		}
		sprintf_s((char*)pbAppended, dwAppendedSize, "%s%s%s",
			brc4Config->prepended.c_str(), brc4Config->onlinePack.c_str(), brc4Config->appended.c_str());
		brc4Config->onlinePack = (char*)pbAppended;
		MVirtualFree(pbAppended);
	}

	if (!HttpSendRequestA(hReq, 0, 0, (LPVOID)brc4Config->onlinePack.c_str(), brc4Config->onlinePack.size())) {
		PrintErrorMsg("HttpSendRequestA");
		CleanupError();
	}

CLEAR_EXIT:
	DeleteWinINetHandle(hInterNet);
	DeleteWinINetHandle(hConnect);
	DeleteWinINetHandle(hReq);
	return bResult;
}

/// <summary>
/// Print the found abnormal Context memory process
/// </summary>
void Brc4::PrintFindSuspiciousContext()
{
	for (auto it = Findings.begin(); it != Findings.end(); ++it)
	{
		auto finding = it->get();
		printf("-----\n");
		printf("Detail: %s\n", finding->details.c_str());
		printf("PID: %d\n", finding->pid);
		if (finding->processName != L"")
		{
			printf("Process: %ws\n", finding->processName.c_str());
		}
		printf("-----\n");
	}
}

/// <summary>
/// Determine whether the memory permission flag has execution permission
/// </summary>
/// <param name="dwProtect"></param>
/// <returns></returns>
inline BOOL Brc4::IsExecuteSet(DWORD dwProtect)
{
	if ((dwProtect == PAGE_EXECUTE) || (dwProtect == PAGE_EXECUTE_READ) ||
		(dwProtect == PAGE_EXECUTE_READWRITE) || (dwProtect == PAGE_EXECUTE_WRITECOPY))
	{
		return true;
	}

	return false;
}

/// <summary>
/// Compare whether the current Context rip is the VirtualProtect function address
/// </summary>
/// <param name="vpFunctions"></param>
/// <param name="iCount"></param>
/// <param name="dwFunction"></param>
/// <returns></returns>
inline BOOL Brc4::VirtualProtectFunction(void** vpFunctions, int iCount, DWORD64 dwFunction)
{
	for (int i = 0; i < iCount; i++)
	{
		if (vpFunctions[i] == (void*)dwFunction)
		{
			return true;
		}
	}

	return false;
}

/// <summary>
/// Traversing the current memory to find suspicious VirtualProtect Context memory
/// </summary>
/// <param name="processInfo"></param>
/// <param name="pBuf"></param>
/// <param name="szBuf"></param>
/// <returns></returns>
BOOL Brc4::FindSuspiciousContext(ProcessInfo& processInfo, void* pBuf, SIZE_T szBuf)
{
	if (szBuf < sizeof(CONTEXT))
	{
		return false;
	}
	CONTEXT* pCtx;
	int count = 5;
	void* vpFunctions[10];
	vpFunctions[0] = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtProtectVirtualMemory");
	vpFunctions[1] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");
	vpFunctions[2] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtectEx");
	vpFunctions[3] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtect");
	vpFunctions[4] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtectEx");

	for (int i = 0; i < szBuf - sizeof(CONTEXT); i += 8)
	{
		char* pcBuf = (char*)pBuf;
		pCtx = (CONTEXT*)&pcBuf[i];
		if ((pCtx->ContextFlags & CONTEXT_CONTROL) &&
			VirtualProtectFunction(vpFunctions, count, pCtx->Rip) &&
			(IsExecuteSet((DWORD)pCtx->R8) || IsExecuteSet((DWORD)pCtx->R9)))
		{
			DWORD64 target = 0;
			if (pCtx->Rcx == (DWORD64)-1)
				target = pCtx->Rdx;
			else
				target = pCtx->Rcx;

			auto finding = std::make_unique<Finding>();

			finding->pid = processInfo.pid;
			finding->processName = processInfo.imageName;
			finding->details = std::format(
				"Suspicious CONTEXT structure pointing to VirtualProtect class function. Target: "
				"{:016x}",
				target);
			Findings.push_back(std::move(finding));
			return true;
		}
	}
	return false;
}