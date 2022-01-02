#pragma once

#include <iostream>
#include <vector>
#include "cJSON.h"
#include "Base64.h"

#pragma warning (disable : 4996)

class Conversion
{
public:
	static std::string vectorToString(std::vector<std::string>(input));
	static std::string wcharToString(wchar_t input[1024]);
	static std::string base64Encode(cJSON* dataRequest);
	static wchar_t* charArrayToLPCWSTR(char* charArray);
	static wchar_t* charToWChar(const char* text);
};
