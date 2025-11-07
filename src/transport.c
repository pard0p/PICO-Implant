#include <windows.h>
#include "includes/HTTP.h"

WINBASEAPI _Ret_maybenull_ HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);

char * go(char * path) {
	KERNEL32$LoadLibraryA("WINHTTP");

	HttpHandle *http_client = HttpInit(0);

	HttpURI uri = {"localhost", 8000, path};
	HttpResponse response = {0};
	HttpRequest(
		http_client,
		HTTP_METHOD_GET,
		&uri,
		NULL,
		NULL,
		&response
	);

	return response.body;
}