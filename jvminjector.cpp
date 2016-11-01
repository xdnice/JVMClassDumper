#include <windows.h>
#include <jni.h>
#include <tlhelp32.h>


void Inject(unsigned long PID, const char *dllname)
{
	DWORD hLibModule;

	HMODULE hKernel32 = GetModuleHandle(TEXT("Kernel32"));

	void *hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE, false, PID);
	int cch = strlen(dllname) + 1;
	void *pLibRemote = VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT,
		PAGE_READWRITE);

	WriteProcessMemory(hProcess, pLibRemote, (void *)dllname, cch, NULL);

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(PTHREAD_START_ROUTINE)
		GetProcAddress(hKernel32,
			"LoadLibraryA"),
		pLibRemote, 0, NULL);

}



int main(int argc, char** argv) {

	if (argc < 2 ) {
		printf("Usage: jvmdump ImageName\n or: jvmdump PID\n");
		getc(stdin);
		return 1;
	}

	int pid = -1;
	

	char* x = argv[1];
	WCHAR searchstring[1024];

	for (; x != '\0' && *x <= '9' && *x >= '0'; x++);
	if (*x == '\0') {
		// numeric
		if (_snscanf(argv[1], strlen(argv[1]), "%d", &pid) != 1) {
			printf("Could not read PID?\n");
			pid = -1; // continue and try to use it as an image name
		}
	}

	if (pid == -1) {
		WCHAR* ss = searchstring;
		for (x = argv[1]; *x != '\0'; x++) {
			*ss++ = *x;
		}
		*ss = 0;
	}

	char* dllname = "jvminjectdll.dll";

	char filepath[1024];
	if (GetModuleFileNameA(NULL, filepath, 1023) > 0) {
		char* x = NULL;
		for (x = filepath + strlen(filepath) - 1; x != filepath && *x != '\\'; --x);
		x++;
		*x = '\0';
		strncat(filepath, dllname, strlen(dllname));
		printf("path: %s\n", filepath);
	}



	char* dll = filepath; 
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	int injections = 0;
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if ((pid == -1 && wcsicmp(entry.szExeFile, searchstring) == 0) || pid == entry.th32ProcessID)
			{
				printf("Injecting PID %d\n", entry.th32ProcessID);
				Inject(entry.th32ProcessID, dll);
				injections++;
			}
		}
	}

	CloseHandle(snapshot);
	if (injections == 0) {
		printf("Could not find specified process!!!\n");

	}
	else {
		printf("Injected into %d processes according to specified search\n", injections);
	}
	printf("Finished. Press any key to close this window.");
	getc(stdin);
	return 0;

}
