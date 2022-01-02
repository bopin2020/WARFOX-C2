// use the hashing header and resolution .cpp file along with this
// build out the array of function names to generate hashes for


#include <stdio.h>

#include "resolve.h"
#include <windows.h>
#include <winternl.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")
#include "Definitions.h"

int main(int argc, char** argv)
{
	//httpCall();

	const char* apiHash[1] = {
		"CreateThread"
	};

	for (int i = 0; i < sizeof(apiHash) / sizeof(apiHash[0]); i++)
	{
		UINT32 u32Hash = 0;
		if ((u32Hash = resolve_hash_name(apiHash[i])) != 0)
		{
			printf("{0x%X, , NULL}, // %s \t\t hash_%s = (_%s)rtExampleTbl.reEntries[].lpAddr; \t\t static _%s hash_%s = NULL;\n",
				u32Hash, apiHash[i], apiHash[i], apiHash[i], apiHash[i], apiHash[i]);
		}
	}

	getchar();
}