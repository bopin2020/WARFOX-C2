#pragma once

#include "aes.hpp"
#include "MD5.h"

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <WinInet.h>
#include <cstring>

class Encrypt
{
public:
	static std::vector<std::string> parseConfiguration(std::string decrypted_config);
	static std::vector<std::string> returnConfigValues();
	static std::vector<unsigned char> encryptNetworkTraffic(std::string data_to_encrypt);
};