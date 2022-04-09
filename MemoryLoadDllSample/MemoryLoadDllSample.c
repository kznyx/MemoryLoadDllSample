// MemoryLoadDllSample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <Windows.h>

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

HMODULE Load(LPVOID lpPEBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	LPVOID lpModule = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirecotry = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	PCHAR pDllName = NULL;
	HMODULE hDllModule = NULL;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;
	PUINT_PTR pIAT = NULL;
	UINT_PTR uipFunPtr = 0;
	LPCSTR lpProcName = NULL;
	UINT_PTR uipImageLoadDiff = 0;
	PIMAGE_BASE_RELOCATION pRelocTable = NULL;
	SIZE_T nRelocBlockNum = 0;
	PIMAGE_RELOC pRelocBlock = NULL;
	BOOL bRet = FALSE;
	DLLMAIN pfnDllMain = NULL;
	LPVOID lpParameter = NULL;

	// Dos header
	pDosHeader = (PIMAGE_DOS_HEADER)lpPEBuffer;
	// Nt Header
	pNtHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)lpPEBuffer + pDosHeader->e_lfanew);
	// Alloc memory
	lpModule = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpModule)
	{
		printf("[-] VirtualAlloc failed\r\n");
		return NULL;
	}
	printf("[+] VirtualAlloc successed, %p\r\n", lpModule);
	// Copy PE header
	RtlCopyMemory(lpModule, lpPEBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);
	printf("[+] Copy Pe header successed\r\n");
	// Copy sections
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);
	for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (pSectionHeader->SizeOfRawData != 0)
		{
			RtlCopyMemory(
				(LPVOID)((UINT_PTR)lpModule + pSectionHeader->VirtualAddress),
				(LPVOID)((UINT_PTR)lpPEBuffer + pSectionHeader->PointerToRawData),
				pSectionHeader->SizeOfRawData);
		}
		pSectionHeader++;
	}
	printf("[+] Copy sections successed\r\n");

	// Fix import table
	pDataDirecotry = (PIMAGE_DATA_DIRECTORY)(&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((UINT_PTR)lpModule + pDataDirecotry->VirtualAddress);
	while (pImportDescriptor->Name)
	{
		// Load dll
		pDllName = (PCHAR)((UINT_PTR)lpModule + pImportDescriptor->Name);
		HMODULE hDllModule = LoadLibraryA(pDllName);
		if (!hDllModule)
		{
			printf("[-] LoadLibraryA failed, dll: %s\r\n", pDllName);
			// Next
			pImportDescriptor++;
			continue;
		}
		printf("[+] LoadLibraryA success, dll: %s\r\n", pDllName);

		// FTs
		if (!pImportDescriptor->FirstThunk)
		{
			// Next
			pImportDescriptor++;
			continue;
		}
		pFirstThunk = (PIMAGE_THUNK_DATA)((UINT_PTR)lpModule + pImportDescriptor->FirstThunk);
		pIAT = (PUINT_PTR)pFirstThunk;
		while (pFirstThunk->u1.Ordinal)
		{
			LPCSTR lpProcName = NULL;
			if (!(pFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// Import by name
				lpProcName = (UINT_PTR)lpModule + ((PIMAGE_IMPORT_BY_NAME)pFirstThunk->u1.AddressOfData)->Name;
			}
			else
			{
				lpProcName = (LPCSTR)IMAGE_ORDINAL(pFirstThunk->u1.Ordinal);
			}
			uipFunPtr = (UINT_PTR)GetProcAddress(hDllModule, lpProcName);
			if (!uipFunPtr)
			{
				printf("[-] GetProcAddress failed, %s\r\n", lpProcName);
			}
			printf("[+] GetProcAddress success, %s %p\r\n", lpProcName, (LPVOID)uipFunPtr);

			// Write IAT
			*pIAT = uipFunPtr;

			// Next
			pIAT++;
			pFirstThunk++;
		}

		// Next
		pImportDescriptor++;
	}
	printf("[+] Fix import table successed\r\n");

	// Fix reloc table
	pDataDirecotry = (PIMAGE_DATA_DIRECTORY)(&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (pDataDirecotry->Size > 0)
	{
		uipImageLoadDiff = (UINT_PTR)lpModule - pNtHeader->OptionalHeader.ImageBase;
		pRelocTable = (PIMAGE_BASE_RELOCATION)((UINT_PTR)lpModule + pDataDirecotry->VirtualAddress);
		while (pRelocTable->SizeOfBlock)
		{
			nRelocBlockNum = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			pRelocBlock = (PIMAGE_RELOC)((UINT_PTR)pRelocTable + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t i = 0; i < nRelocBlockNum; i++)
			{
				PUINT_PTR pRelocAddr = (PUINT_PTR)((UINT_PTR)lpModule + pRelocTable->VirtualAddress + pRelocBlock[i].offset);
				if (pRelocBlock[i].type == IMAGE_REL_BASED_HIGHLOW)
				{
					*pRelocAddr += uipImageLoadDiff;
				}
				else if (pRelocBlock[i].type == IMAGE_REL_BASED_DIR64)
				{
					*pRelocAddr += uipImageLoadDiff;
				}
				else if (pRelocBlock[i].type == IMAGE_REL_BASED_HIGH)
				{
					*pRelocAddr += HIWORD(uipImageLoadDiff);
				}
				else if (pRelocBlock[i].type == IMAGE_REL_BASED_LOW)
				{
					*pRelocAddr += LOWORD(uipImageLoadDiff);
				}
			}

			// Next
			pRelocTable = (PIMAGE_BASE_RELOCATION)((UINT_PTR)pRelocTable + pRelocTable->SizeOfBlock);
		}
	}
	printf("[+] Fix reloc table successed\r\n");

	// Entrypoint
	pfnDllMain = (DLLMAIN)((UINT_PTR)lpModule + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	printf("[+] Get DllMain address, %p\r\n", pfnDllMain);
	bRet = pfnDllMain((HINSTANCE)lpModule, DLL_PROCESS_ATTACH, lpParameter);

	return (HMODULE)lpModule;
}

int main(int argc, char** argv)
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	BOOL bRet = FALSE;

	if (argc != 2)
	{
		printf("Useage: path\r\n");
		return 0;
	}

	const char* lpPath = argv[1];

	hFile = CreateFileA(lpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileA failed\r\n");
		return -1;
	}
	dwLength = GetFileSize(hFile, NULL);
	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		printf("[-] HeapAlloc failed\r\n");
		CloseHandle(hFile);
		return -1;
	}
	bRet = ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL);
	if (!bRet || dwBytesRead < dwLength)
	{
		printf("[-] ReadFile failed\r\n");
		HeapFree(GetProcessHeap(), 0, lpBuffer);
		CloseHandle(hFile);
		return -1;
	}
	CloseHandle(hFile);

	hModule = Load(lpBuffer);
	printf("[+] Memory load successed, module address: %p\r\n", hModule);

	return 0;
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
