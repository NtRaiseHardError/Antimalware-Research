#pragma once
#ifndef __ANTIHOOK_H__
#define __ANTIHOOK_H__

#include <Windows.h>

#define SIZEOF_FUNC_NAME 256

/*
 * Struct that describes a hooked function.
 * 
 * Members:
 * - hModule: Handle to the function's module.
 * - dwOrdinal: The ordinal number of the function.
 * - lpFuncAddress: The address of the function.
 * - szFuncName: Name of the function, if it exists.
 * - szHookModuleName: Name of the hooked module, if it exists.
 * - lpHookAddress: Destinaton of the address of the redirection.
 */
typedef struct _HOOK_FUNC_INFO {
	HMODULE hModule;							// Module of the hooked function, if exists.
	DWORD dwOrdinal;							// Ordinal of the function.
	LPVOID lpFuncAddress;						// Address of the function.
	CHAR szFuncName[SIZEOF_FUNC_NAME];			// Name of hooked function.
	CHAR szHookModuleName[SIZEOF_FUNC_NAME];	// Name of the hooking module, if exists.
	LPVOID lpHookAddress;						// Destinaton of the address of the redirection.
} HOOK_FUNC_INFO, *LPHOOK_FUNC_INFO;

/*
 * NewHookFuncInfo
 * Returns a heap-allocated pointer to HOOK_FUNC_INFO. The pointer can be freed using the
 * FreeHookFuncInfo function.
 *
 * Returns an LPHOOK_FUNC_INFO if successful, else, NULL.
 */
LPHOOK_FUNC_INFO NewHookFuncInfo(void);

/*
 * FreeHookFuncInfo
 * Frees the heap-allocated resource provided by the NewHookFuncInfo function. The pointer
 * is set to NULL after being released.
 *
 * Parameters:
 * - info: Reference to a heap-allocated pointer to HOOK_FUNC_INFO.
 *
 * Returns TRUE on success, else, FALSE.
 */
BOOL FreeHookFuncInfo(LPHOOK_FUNC_INFO *info);

/*
 * GetModules
 * Enumerates the current process's modules.
 *
 * Parameters:
 * - hModules: An array of HMODULES to receive the list of module handles.
 * - nSize: Size of the array of hModules in bytes.
 * - dwNumModules: Number of modules enumerated.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_ENUM_PROCESS_MODULES_FAILED: If the call to EnumProcessModules failed.
 * - ERR_SIZE_TOO_SMALL: If the hModules array is too small. Call the function again with a
 * larger array.
 */
DWORD GetModules(HMODULE *hModules, const DWORD nSize, LPDWORD dwNumModules);

/*
 * GetModuleName
 * Retrieves the full path name of the desired module.
 *
 * Parameters:
 * - hModule: The handle to the desired module.
 * - szModuleName: The array to receive the full path name.
 * - nSize: The size of the array in bytes.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MOD_NAME_NOT_FOUND: The name of the module does not exist. szModuleName will
 * be contain the "<not found>" string.
 */
DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize);


DWORD CheckModuleForHooks(const HMODULE hModule, LPHOOK_FUNC_INFO *infos, const SIZE_T nSize, LPDWORD cbNeeded);

/*
 * UnhookModule
 * Attempts to unhook a given module. The module is located by retrieving the full path name
 * of the desired module and then mapped into the process. The newly-mapped module is then
 * used to recover a clean copy of the code section with which it is used to overwrite the
 * original module.
 *
 * Parameters:
 * - hModule: The module to be unhooked.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MOD_NAME_NOT_FOUND: If the full path name of the module is not found.
 * - ERR_CREATE_FILE_FAILED: If access a handle to the module's file failed.
 * - ERR_CREATE_FILE_MAPPING_FAILED: If the file mapping object already exists.
 * - ERR_MAP_FILE_FAILED: If mapping the module's file failed.
 */
DWORD UnhookModule(const HMODULE hModule);

#endif // !__ANTIHOOK_H__
