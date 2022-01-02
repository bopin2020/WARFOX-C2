#include "Uninstall.h"

static HANDLE ds_open_handle(PWCHAR pwPath)
{
	return CreateFileW(pwPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static BOOL ds_rename_handle(HANDLE hHandle)
{
	const wchar_t* lpwStream = L":null";

	FILE_RENAME_INFO fRename;
	RtlSecureZeroMemory(&fRename, sizeof(fRename));

	fRename.FileNameLength = sizeof(lpwStream);
	RtlCopyMemory(fRename.FileName, lpwStream, sizeof(lpwStream));

	return SetFileInformationByHandle(hHandle, FileRenameInfo, &fRename, sizeof(fRename) + sizeof(lpwStream));
}

static BOOL ds_deposite_handle(HANDLE hHandle)
{
	FILE_DISPOSITION_INFO fDelete;
	RtlSecureZeroMemory(&fDelete, sizeof(fDelete));

	fDelete.DeleteFile = TRUE;

	return SetFileInformationByHandle(hHandle, FileDispositionInfo, &fDelete, sizeof(fDelete));
}

void Uninstall::SelfDelete()
{
	WCHAR wcPath[MAX_PATH + 1];
	RtlSecureZeroMemory(wcPath, sizeof(wcPath));

	// get the path to the current running process ctx
	GetModuleFileNameW(NULL, wcPath, MAX_PATH);

	HANDLE hCurrent = ds_open_handle(wcPath);

	ds_rename_handle(hCurrent);

	CloseHandle(hCurrent);

	hCurrent = ds_open_handle(wcPath);

	FILE_DISPOSITION_INFO fDelete;
	RtlSecureZeroMemory(&fDelete, sizeof(fDelete));

	fDelete.DeleteFile = TRUE;

	SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

	CloseHandle(hCurrent);
}