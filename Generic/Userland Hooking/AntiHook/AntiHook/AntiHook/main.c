/*
 * TODO: x86 has a bug, maybe it exists in x64 too.
 * Maybe this entire project is a bug itself.
 * Who really knows...?
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <Windows.h>

#include "AntiHook.h"
#include "err.h"

// Calculates the number of elements in an array.
#define SIZEOF_ARRAY(x) ((sizeof(x))/(sizeof(*x)))

// Console colours.
#define CONSOLE_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_RED FOREGROUND_RED
#define CONSOLE_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_DARK_GREEN FOREGROUND_GREEN
#define CONSOLE_BLUE FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define CONSOLE_DARK_BLUE FOREGROUND_BLUE
#define CONSOLE_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_YELLOW FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_YELLOW FOREGROUND_GREEN | FOREGROUND_RED
#define CONSOLE_PURPLE FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_PURPLE FOREGROUND_BLUE | FOREGROUND_RED
#define CONSOLE_WHITE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_GRAY FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

typedef enum _DEBUG_LEVEL {
	DEBUG_INFO,
	DEBUG_SUCCESS,
	DEBUG_WARNING,
	DEBUG_ERROR
} DEBUG_LEVEL;

CHAR dbgSym[] = {
	'*',	// DEBUG_INFO.
	'+',	// DEBUG_SUCCESS.
	'!',	// DEBUG_WARNING.
	'-'		// DEBUG_ERROR.
};

WORD dbgColour[] = {
	CONSOLE_WHITE,	// DEBUG_INFO.
	CONSOLE_GREEN,	// DEBUG_SUCCESS.
	CONSOLE_YELLOW,	// DEBUG_WARNING.
	CONSOLE_RED		// DEBUG_ERROR.
};

#define PRINT_INFO(fmt, ...) PrintDebug(DEBUG_INFO, fmt, __VA_ARGS__)
#define PRINT_SUCCESS(fmt, ... ) PrintDebug(DEBUG_SUCCESS, fmt, __VA_ARGS__)
#define PRINT_WARNING(fmt, ...) PrintDebug(DEBUG_WARNING, fmt, __VA_ARGS__)
#define PRINT_ERROR(fmt, ...) PrintDebug(DEBUG_ERROR, fmt, __VA_ARGS__)

/*
 * Struct to group the HOOK_FUNC_INFO structures by their module.
 *
 * Members:
 * - hModule: Handle to the hooked module.
 * - szModuleName: ASCII C string of the full path of the module.
 * - dwNumHooks: Number of hooks in the module.
 * - infos: Pointer to an array of HOOK_FUNC_INFO structures.
 */
typedef struct _MODULE_HOOK_INFO {
	HMODULE hModule;				// Handle to the hooked module.
	CHAR szModuleName[MAX_PATH];	// Full path to module name.
	DWORD dwNumHooks;				// Number of hooks in the module.
	LPHOOK_FUNC_INFO infos[1024];	// Hooked functions information.
} MODULE_HOOK_INFO, *LPMODULE_HOOK_INFO;

void PrintColour(const WORD wColour, const LPSTR fmt, ...) {
	// Save the state of the console.
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
	// Change console colour.
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wColour);

	// Print variadic arguments.
	va_list ap;
	va_start(ap, fmt);

	vprintf(fmt, ap);

	va_end(ap);

	// Restore original state of the console.
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), info.wAttributes);
}

void PrintDebug(const DEBUG_LEVEL l, const LPSTR fmt, ...) {
	// Print variadic arguments.
	va_list ap;
	va_start(ap, fmt);

	printf("[");
	PrintColour(dbgColour[l], "%c", dbgSym[l]);
	printf("] ");
	vprintf(fmt, ap);

	va_end(ap);
}

void PrintHookFuncInfo(const LPHOOK_FUNC_INFO info) {
	PRINT_WARNING("");

	PrintColour(CONSOLE_GREEN, "%s", info->szFuncName);
	printf(" (ordinal: ");
	PrintColour(CONSOLE_PURPLE, "%u", info->dwOrdinal);
	printf(") hooked at [");
#ifdef _WIN64
	PrintColour(CONSOLE_RED, "0x%016p", info->lpHookAddress);
#else
	PrintColour(CONSOLE_RED, "0x%08p", info->lpHookAddress);
#endif
	printf("]\n");
	printf("\tModule name : ");
	PrintColour(CONSOLE_DARK_YELLOW, "%s\n", info->szHookModuleName);
}

void PrintBanner(void) {
	WORD wColours[] = {
		//CONSOLE_RED,
		CONSOLE_DARK_RED,
		CONSOLE_GREEN,
		//CONSOLE_DARK_GREEN,
		CONSOLE_BLUE,
		//CONSOLE_DARK_BLUE,
		CONSOLE_CYAN,
		//CONSOLE_YELLOW,
		CONSOLE_DARK_YELLOW,
		CONSOLE_PURPLE,
		//CONSOLE_DARK_PURPLE,
		//CONSOLE_WHITE,
		CONSOLE_GRAY
	};

	// lol
	srand((unsigned int)__rdtsc());

	PrintColour(
		wColours[rand() % SIZEOF_ARRAY(wColours)],
		" ________  ________   _________  ___  ___  ___  ________  ________  ___  __       \n"
		"|\\   __  \\|\\   ___  \\|\\___   ___\\\\  \\|\\  \\|\\  \\|\\   __  \\|\\   __  \\|\\  \\|\\  \\     \n"
		"\\ \\  \\|\\  \\ \\  \\\\ \\  \\|___ \\  \\_\\ \\  \\ \\  \\\\\\  \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|_   \n"
		" \\ \\   __  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\ \\   __  \\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\   ___  \\  \n"
		"  \\ \\  \\ \\  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\ \\  \\ \\  \\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\  \\\\ \\  \\ \n"
		"   \\ \\__\\ \\__\\ \\__\\\\ \\__\\   \\ \\__\\ \\ \\__\\ \\__\\ \\__\\ \\_______\\ \\_______\\ \\__\\\\ \\__\\\n"
		"    \\|__|\\|__|\\|__| \\|__|    \\|__|  \\|__|\\|__|\\|__|\\|_______|\\|_______|\\|__| \\|__|\n\n"
	);
}

/*
 * AddModule
 * Returns a handle to a module if it exists, otherwise, loads a new module using
 * LoadLibrary and returns a handle to the module if successful.
 *
 * Parameters:
 * - lpLibName: Pointer to an ASCII C string of the desired module.
 *
 * Returns an HMDOULE of the desired module if successful, else, NULL.
 */
HMODULE AddModule(const LPSTR lpLibName) {
	HMODULE hModule = GetModuleHandleA(lpLibName);
	if (!hModule) {
		hModule = LoadLibraryA(lpLibName);
	}

	return hModule;
}

/*
 * NewModuleHookInfo
 * Returns a heap-allocated pointer to an array of heap-allocated MODULE_HOOK_INFO
 * structures. The pointer can be freed using the FreeModuleHookInfo function.
 *
 * Parameters:
 * - nSize: Desired number of elements of the array.
 *
 * Returns an LPMODULE_HOOK_INFO pointer if successful, else, NULL.
 */
LPMODULE_HOOK_INFO *NewModuleHookInfo(SIZE_T nSize) {
	// Create a pointer to an array of MODULE_HOOK_INFO.
	LPMODULE_HOOK_INFO *mods = (LPMODULE_HOOK_INFO *)HeapAlloc(
		GetProcessHeap(),					// Handle to heap.
		HEAP_ZERO_MEMORY,					// Heap allocation flag options.
		sizeof(LPMODULE_HOOK_INFO) * nSize	// Number of bytes to be allocated.
	);

	if (!mods) {
		return NULL;
	}

	for (SIZE_T i = 0; i < nSize; i++) {
		// Allocate a LPMODULE_HOOK_INFO.
		mods[i] = (LPMODULE_HOOK_INFO)HeapAlloc(
			GetProcessHeap(),			// Handle to heap.
			HEAP_ZERO_MEMORY,			// Heap allocation flag options.
			sizeof(MODULE_HOOK_INFO)	// Number of bytes to be allocated.
		);

		ZeroMemory(mods[i]->szModuleName, sizeof(mods[i]->szModuleName));
		mods[i]->dwNumHooks = 0;
		ZeroMemory(mods[i]->infos, sizeof(mods[i]->infos));
	}

	return mods;
}

/*
 * FreeModuleHookInfo
 * Frees the heap-allocated resource provided by the NewModuleHookInfo function.
 *
 * Parameters:
 * - mod: Pointer to the LPMODULE_HOOK_INFO.
 * - nSize: Number of allocated elements.
 *
 * Returns TRUE if successful, else, FALSE???
 */
BOOL FreeModuleHookInfo(LPMODULE_HOOK_INFO *mod, SIZE_T nSize) {
	// Free each LPMODULE_HOOK_INFO.
	for (SIZE_T i = 0; i < nSize; i++) {
		BOOL bRet = HeapFree(
			GetProcessHeap(),	// Handle to heap.
			0,					// Heap free flag options.
			mod[i]				// Pointer to memory to be freed.
		);

		// Avoid dangling pointer.
		mod[i] = NULL;
	}
	
	// Free the LPMODULE_HOOK_INFO array.
	BOOL bRet = HeapFree(
		GetProcessHeap(),	// Handle to heap.
		0,					// Heap free flag options.
		*mod				// Pointer to memory to be freed.
	);

	// Avoid dangling pointer.
	*mod = NULL;

	return bRet;
}

/*
 * TestCreateProcess
 * Calls CreateProcess to check the integrity of the unhooked module's functions. Outputs
 * the process and thread IDs of the created process if successful.
 *
 * Parameters:
 * - lpApplicationName: Pointer to an ASCII C string of the desired application's full
 * path.
 * - bShowWindow: Boolean specifying whether to show or hide the application's window. If 
 * the window is not shown, it will be automatically terminated if the process has been 
 * successfully spawned.
 */
void TestCreateProcess(const LPSTR lpApplicationName, const BOOL bShowWindow) {
	PRINT_INFO("Testing ");
	PrintColour(CONSOLE_GREEN, "CreateProcess");
	printf(" with ");
	PrintColour(CONSOLE_CYAN, "%s\n", lpApplicationName);

	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	// Don't show application window.
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = bShowWindow ? SW_SHOW : SW_HIDE;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	BOOL bRet = CreateProcess(
		lpApplicationName,	// Application path.
		NULL,				// Command line arguments.
		NULL,				// Process security attributes.
		NULL,				// Thread security attributes.
		FALSE,				// Inherit handles.
		0,					// Creation flags.
		NULL,				// Environment.
		NULL,				// Current directory.
		&si,				// Startup information.
		&pi					// Process information.
	);

	if (bRet == TRUE) {
		PRINT_INFO("Process ID: %u\n", pi.dwProcessId);
		PRINT_INFO("Thread ID: %u\n", pi.dwThreadId);
		PRINT_SUCCESS("Test success!\n\n");

		// If process is created, kill it and clean up.
		if (!bShowWindow) {
			TerminateProcess(pi.hProcess, 0);
		}
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	} else {
		DWORD dwError = GetLastError();

		PRINT_ERROR("Test failed: 0x%08x\n\n", dwError);
	}
}

/*
 * AntiHook Theory
 * To unhook the modules in the current process, the modules must first be enumerated 
 * and then individually checked for hooks. If hooks are found, the module's exported 
 * functions should be reverted to their original code.
 *
 * Detecting hooks:
 * To detect if exported functions within a module have been hooked, a handle to the 
 * module must be obtained. Using this handle, the PE structure of the module is parsed to
 * find the list of exported functions from the Optional Header structure's data directory.
 * Once the address of the export directory is located, it should be used to identify the 
 * addresses of the exported functions. The beginning of each function's address can be 
 * analysed for specific patterns of opcodes to identify if there is an instruction pointer 
 * redirect, e.g. using jmps, calls, or push/rets. Since there exists code to redirect code
 * to other parts of the same module, it may be required to also check that the destination 
 * of these redirects are within the same module or not. Obviously, if they are not in the 
 * module, it is hooked by an outside entity.
 *
 * Unhooking hooks:
 * To cleanse the hooks, it is relatively simple. It is assumed here that exported functions 
 * only reside in the .text section (as currently accurate in common system modules such as 
 * ntdll and kernel32). First, a clean version of the module is mapped into the process space
 * using something like CreateFileMapping/MapViewOfFile, specifying that they are images so 
 * that they are properly mapped as an executable file(?). The .text section is then found by 
 * parsing the PE headers and the code within the section is used to overwrite the hooked 
 * module's own .text section. If there is some multithreading happening, it is probably best 
 * to suspend all the threads before performing this or something bad may happen inbetween 
 * the overwrite operation. Multithreading is *NOT* assumed in this code.
 */
int main(int argc, char *argv[]) {
	PrintBanner();

	// Add a random module.
	HMODULE hMod = AddModule("advapi32.dll");

	PRINT_INFO("Detecting hooked modules...\n\n");

	// Get all modules.
	HMODULE hModules[1024];
	ZeroMemory(hModules, sizeof(hModules));
	DWORD dwNumModules = 0;
	DWORD dwRet = GetModules(
		hModules,			// Module handle array.
		sizeof(hModules),	// Size of module handle array in bytes.
		&dwNumModules		// Number of modules enumerated.
	);

	if (dwRet) {
		PRINT_ERROR("%s\n", errStrings[dwRet]);
		return 1;
	}

	LPMODULE_HOOK_INFO *mods = NewModuleHookInfo(dwNumModules);
	if (!mods) {
		PRINT_ERROR("Failed to create module hook infos\n");
		return 1;
	}

	// Total number of hooks across all modules.
	DWORD dwNumHooks = 0;
	// Enumerate all modules and check for hooks.
	for (DWORD i = 0; i < dwNumModules; i++) {
		CHAR szModuleName[MAX_PATH];
		ZeroMemory(szModuleName, sizeof(szModuleName));

		dwRet = GetModuleName(
			hModules[i],			// Module handle.
			szModuleName,			// Buffer to receive name.
			sizeof(szModuleName)	// Size of the buffer.
		);

		if (dwRet) {
			PRINT_ERROR("%s\n", errStrings[dwRet]);
			return 1;
		}

		PRINT_INFO("Checking module ");
		PrintColour(CONSOLE_CYAN, "%s\n", szModuleName);

		// Check for hooks.
		DWORD cbNeeded = 0;
		dwRet = CheckModuleForHooks(
			hModules[i],					// Module handle.
			mods[i]->infos,					// Pointer to an array of LPHOOK_FUNC_INFOs.
			SIZEOF_ARRAY(mods[i]->infos),	// Number of *elements* in the LPHOOK_FUNC_INFO array.
			&cbNeeded						// Number of *elements* required to store all module 
											// handles.
		);

		if (dwRet) {
			PRINT_ERROR("%s\n", errStrings[dwRet]);
			//return 1;
		}

		// Print out hooked information.
		if (cbNeeded == 0) {
			PRINT_SUCCESS("No hooks detected!\n");
		} else {
			for (DWORD j = 0; j < cbNeeded; j++) {
				PrintHookFuncInfo(mods[i]->infos[j]);
			}
		}
		puts("");

		// Copy the module handle.
		mods[i]->hModule = hModules[i];
		// Copy the number of hooks in the module.
		mods[i]->dwNumHooks = cbNeeded;
		// Copy the path of the module.
		strncpy(mods[i]->szModuleName, szModuleName, sizeof(mods[i]->szModuleName) - 1);
		dwNumHooks += cbNeeded;
	}

	// Check if there were any detected hooks.
	if (dwNumHooks > 0) {
		PRINT_INFO("Attempting to unhook modules...\n\n");

		// Replace hooks with original.
		for (DWORD i = 0; i < dwNumModules; i++) {
			// Unhook only if there are detected hooks.
			if (mods[i]->dwNumHooks > 0) {
				PRINT_INFO("Unhooking ");
				PrintColour(CONSOLE_CYAN, "%s", mods[i]->szModuleName);
				printf(" at [");
				PrintColour(CONSOLE_RED, "0x%016p", (LPVOID)mods[i]->hModule);
				printf("]\n");
				
				// Unhook!
				dwRet = UnhookModule(mods[i]->hModule);

				if (dwRet) {
					PRINT_ERROR("%s\n", errStrings[dwRet]);
					return 1;
				}
			}
		}
		puts("");

		// Check for hooks again.
		for (DWORD i = 0; i < dwNumModules; i++) {
			// Only check hooked modules.
			if (mods[i]->dwNumHooks > 0) {
				PRINT_INFO("Checking module ");
				PrintColour(CONSOLE_CYAN, "%s\n", mods[i]->szModuleName);
				
				LPHOOK_FUNC_INFO newInfos[1024];
				ZeroMemory(newInfos, sizeof(newInfos));
				DWORD newCbNeeded = 0;
				dwRet = CheckModuleForHooks(
					mods[i]->hModule,
					newInfos,
					SIZEOF_ARRAY(newInfos),
					&newCbNeeded
				);

				if (dwRet) {
					PRINT_ERROR("%s\n", errStrings[dwRet]);
					//return 1;
				}

				// Print results.
				if (newCbNeeded == 0) {
					// Hopefully, we get here!
					PRINT_SUCCESS("No hooks detected!\n");
				} else {
					// Sad times if we get here. :(
					for (DWORD i = 0; i < newCbNeeded; i++) {
						// Print out the hook information.
						PrintHookFuncInfo(newInfos[i]);
						// Free info struct.
						FreeHookFuncInfo(&newInfos[i]);
					}
				}
				puts("");
			}
		}

		// Test an unhooked function.
		TestCreateProcess("C:\\Windows\\system32\\calc.exe", TRUE);

		// Clean up.
		for (DWORD i = 0; i < dwNumModules; i++) {
			for (DWORD j = 0; j < mods[i]->dwNumHooks; j++) {
				FreeHookFuncInfo(&mods[i]->infos[j]);
			}
		}

		FreeModuleHookInfo(mods, dwNumModules);
	}

	// Free the randomly added module.
	if (hMod) {
		FreeModule(hMod);
	}

	PRINT_INFO("Done.");

	// Pause console.
	//PRINT_INFO("Press enter to continue.");
	getchar();

	return 0;
}
