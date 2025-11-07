#include "HTTP.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tchar.h>

/**
 * WinHTTP API Functions
 */
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpen(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSetOption(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
);

WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
);

WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSendRequest(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReceiveResponse(
    HINTERNET hRequest,
    LPVOID lpReserved
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryHeaders(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPCWSTR pwszName,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryDataAvailable(
    HINTERNET hRequest,
    LPDWORD lpdwNumberOfBytesAvailable
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReadData(
    HINTERNET hRequest,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);

WINBASEAPI BOOL WINAPI WINHTTP$WinHttpCloseHandle(
    HINTERNET hInternet
);

WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);

WINBASEAPI void MSVCRT$memset(void *s, int c, size_t n);

WINBASEAPI errno_t MSVCRT$strcpy_s(char *strDestination, size_t numberOfElements, const char *strSource);

WINBASEAPI size_t MSVCRT$strlen(const char *str);

WINBASEAPI int MSVCRT$strcmp(const char *s1, const char *s2);

WINBASEAPI void MSVCRT$free(void *ptr);

WINBASEAPI void* MSVCRT$realloc(void *ptr, size_t size);

WINBASEAPI int MSVCRT$_snwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, ...);

WINBASEAPI size_t MSVCRT$wcslen(const wchar_t *str);

WINBASEAPI int KERNELBASE$MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
);

WINBASEAPI int KERNELBASE$WideCharToMultiByte(
    UINT CodePage,
    DWORD dwFlags,
    LPCWCH lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar
);

/* ============================================================================
 * Internal Function Declarations
 * ============================================================================ */

/**
 * Convert UTF-8 string to wide character string.
 */
static LPWSTR HttpUtf8ToWide(const char *utf8_string);

/**
 * Convert wide character string to UTF-8 string.
 */
static char* HttpWideToUtf8(LPWSTR wide_string);

/**
 * Convert HttpMethod enum to WinHTTP method string.
 */
static const LPWSTR HttpMethodToWideString(HttpMethod method);

/* ============================================================================
 * Core Functions Implementation
 * ============================================================================ */

HttpHandle* HttpInit(DWORD https_enabled) {
    HttpHandle *client = (HttpHandle*)MSVCRT$malloc(sizeof(HttpHandle));
    if (!client) {
        return NULL;
    }

    /* Initialize all fields */
    MSVCRT$memset(client, 0, sizeof(HttpHandle));
    client->https_enabled = https_enabled;
    client->response_timeout_ms = 30000;  /* Default 30 seconds */
    MSVCRT$strcpy_s(client->user_agent, sizeof(client->user_agent), "LibHttp/1.0");

    /* Create WinHTTP session */
    client->session_handle = WINHTTP$WinHttpOpen(
        L"LibHttp/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!client->session_handle) {
        MSVCRT$free(client);
        return NULL;
    }

    /* Set default options on session */
    DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WINHTTP$WinHttpSetOption(client->session_handle, WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_protocols, sizeof(secure_protocols));

    return client;
}

void HttpDestroy(HttpHandle *handle) {
    if (!handle) {
        return;
    }

    /* Close connection if open */
    if (handle->connection_handle) {
        WINHTTP$WinHttpCloseHandle(handle->connection_handle);
        handle->connection_handle = NULL;
    }

    /* Close session */
    if (handle->session_handle) {
        WINHTTP$WinHttpCloseHandle(handle->session_handle);
        handle->session_handle = NULL;
    }

    MSVCRT$free(handle);
}

/* ============================================================================
 * Internal Functions Implementation
 * ============================================================================ */


BOOL HttpRequest(HttpHandle *handle, HttpMethod method, const HttpURI *uri, const HttpHeaders *headers, const HttpBody *body, HttpResponse *response) {
    if (!handle || !uri || !uri->host || !uri->path || !response) {
        return FALSE;
    }

    /* Convert strings to wide characters */
    LPWSTR wide_host = HttpUtf8ToWide(uri->host);
    LPWSTR wide_path = HttpUtf8ToWide(uri->path);
    const LPWSTR wide_method = HttpMethodToWideString(method);

    if (!wide_host || !wide_path) {
        MSVCRT$free(wide_host);
        MSVCRT$free(wide_path);
        return FALSE;
    }

    /* Create or reuse connection */
    if (!handle->connection_handle) {
        handle->connection_handle = WINHTTP$WinHttpConnect(
            handle->session_handle,
            wide_host,
            uri->port,
            0
        );
        if (!handle->connection_handle) {
            MSVCRT$free(wide_host);
            MSVCRT$free(wide_path);
            return FALSE;
        }
    }

    /* Create request */
    HINTERNET request_handle = WINHTTP$WinHttpOpenRequest(
        handle->connection_handle,
        wide_method,
        wide_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        handle->https_enabled ? WINHTTP_FLAG_SECURE : 0
    );
    if (!request_handle) {
        MSVCRT$free(wide_host);
        MSVCRT$free(wide_path);
        return FALSE;
    }

    /* Disable SSL certificate verification (trust all certificates) */
    if (handle->https_enabled) {
        DWORD ssl_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WINHTTP$WinHttpSetOption(request_handle, WINHTTP_OPTION_SECURITY_FLAGS, &ssl_flags, sizeof(ssl_flags));
    }

    /* Set timeouts */
    WINHTTP$WinHttpSetOption(request_handle, WINHTTP_OPTION_CONNECT_TIMEOUT, &handle->response_timeout_ms, sizeof(handle->response_timeout_ms));
    WINHTTP$WinHttpSetOption(request_handle, WINHTTP_OPTION_RECEIVE_TIMEOUT, &handle->response_timeout_ms, sizeof(handle->response_timeout_ms));
    WINHTTP$WinHttpSetOption(request_handle, WINHTTP_OPTION_SEND_TIMEOUT, &handle->response_timeout_ms, sizeof(handle->response_timeout_ms));

    /* Add headers */
    SIZE_T header_buffer_size = 4096;
    LPWSTR header_buffer = (LPWSTR)MSVCRT$malloc(header_buffer_size * sizeof(WCHAR));
    if (!header_buffer) {
        WINHTTP$WinHttpCloseHandle(request_handle);
        MSVCRT$free(wide_host);
        MSVCRT$free(wide_path);
        return FALSE;
    }
    MSVCRT$memset(header_buffer, 0, header_buffer_size * sizeof(WCHAR));

    LPWSTR header_ptr = header_buffer;
    SIZE_T header_buffer_remaining = header_buffer_size - 1;

    /* Add User-Agent if not already in custom headers */
    int32_t user_agent_in_headers = 0;
    DWORD header_count = headers ? headers->count : 0;
    HttpHeader *header_array = headers ? headers->headers : NULL;
    for (DWORD i = 0; i < header_count; i++) {
        if (MSVCRT$strcmp(header_array[i].name, "User-Agent") == 0) {
            user_agent_in_headers = 1;
            break;
        }
    }

    if (!user_agent_in_headers) {
        LPWSTR wide_user_agent = HttpUtf8ToWide(handle->user_agent);
        if (wide_user_agent) {
            SIZE_T needed = MSVCRT$_snwprintf_s(header_ptr, header_buffer_remaining, _TRUNCATE, L"User-Agent: %s\r\n", wide_user_agent);
            if (needed > 0) {
                header_ptr += needed;
                header_buffer_remaining -= needed;
            }
            MSVCRT$free(wide_user_agent);
        }
    }

    /* Add custom headers */
    for (DWORD i = 0; i < header_count; i++) {
        LPWSTR wide_name = HttpUtf8ToWide(header_array[i].name);
        LPWSTR wide_value = HttpUtf8ToWide(header_array[i].value);
        if (wide_name && wide_value) {
            SIZE_T needed = MSVCRT$_snwprintf_s(header_ptr, header_buffer_remaining, _TRUNCATE, L"%s: %s\r\n", wide_name, wide_value);
            if (needed > 0) {
                header_ptr += needed;
                header_buffer_remaining -= needed;
            }
        }
        MSVCRT$free(wide_name);
        MSVCRT$free(wide_value);
    }

    /* Prepare body */
    const BYTE *body_data = body ? body->data : NULL;
    SIZE_T body_size = body ? body->size : 0;

    /* Send request */
    BOOL send_result = WINHTTP$WinHttpSendRequest(
        request_handle,
        header_buffer[0] != 0 ? header_buffer : WINHTTP_NO_ADDITIONAL_HEADERS,
        header_buffer[0] != 0 ? MSVCRT$wcslen(header_buffer) : 0,
        (LPVOID)body_data,
        (DWORD)body_size,
        (DWORD)body_size,
        0
    );

    if (!send_result) {
        WINHTTP$WinHttpCloseHandle(request_handle);
        MSVCRT$free(wide_host);
        MSVCRT$free(wide_path);
        MSVCRT$free(header_buffer);
        return FALSE;
    }

    /* Receive response */
    if (!WINHTTP$WinHttpReceiveResponse(request_handle, NULL)) {
        WINHTTP$WinHttpCloseHandle(request_handle);
        MSVCRT$free(wide_host);
        MSVCRT$free(wide_path);
        MSVCRT$free(header_buffer);
        return FALSE;
    }

    /* Get status code */
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (!WINHTTP$WinHttpQueryHeaders(request_handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        status_code = 0;
    }
    response->status_code = status_code;

    /* Get Content-Type header */
    LPWSTR content_type_buffer = (LPWSTR)MSVCRT$malloc(256 * sizeof(WCHAR));
    DWORD content_type_size = 256 * sizeof(WCHAR);
    if (content_type_buffer) {
        MSVCRT$memset(content_type_buffer, 0, content_type_size);
        if (WINHTTP$WinHttpQueryHeaders(request_handle, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                                content_type_buffer, &content_type_size, WINHTTP_NO_HEADER_INDEX)) {
            response->content_type = HttpWideToUtf8(content_type_buffer);
        } else {
            response->content_type = (char*)MSVCRT$malloc(1);
            if (response->content_type) {
                response->content_type[0] = '\0';
            }
        }
        MSVCRT$free(content_type_buffer);
    } else {
        response->content_type = (char*)MSVCRT$malloc(1);
        if (response->content_type) {
            response->content_type[0] = '\0';
        }
    }

    /* Read response body */
    SIZE_T total_body_size = 0;
    BYTE *body_buffer = NULL;
    DWORD bytes_available = 0;
    DWORD bytes_read = 0;

    while (WINHTTP$WinHttpQueryDataAvailable(request_handle, &bytes_available) && bytes_available > 0) {
        BYTE *temp_buffer = (BYTE*)MSVCRT$realloc(body_buffer, total_body_size + bytes_available);
        if (!temp_buffer) {
            MSVCRT$free(body_buffer);
            WINHTTP$WinHttpCloseHandle(request_handle);
            MSVCRT$free(wide_host);
            MSVCRT$free(wide_path);
            MSVCRT$free(header_buffer);
            return FALSE;
        }
        body_buffer = temp_buffer;
        if (!WINHTTP$WinHttpReadData(request_handle, &body_buffer[total_body_size], bytes_available, &bytes_read)) {
            MSVCRT$free(body_buffer);
            WINHTTP$WinHttpCloseHandle(request_handle);
            MSVCRT$free(wide_host);
            MSVCRT$free(wide_path);
            MSVCRT$free(header_buffer);
            return FALSE;
        }
        total_body_size += bytes_read;
    }

    /* Add null terminator to body (for string-like access) */
    if (total_body_size > 0 || body_buffer == NULL) {
        BYTE *temp_buffer = (BYTE*)MSVCRT$realloc(body_buffer, total_body_size + 1);
        if (temp_buffer) {
            body_buffer = temp_buffer;
            body_buffer[total_body_size] = '\0';
        }
    }

    response->body = (char*)body_buffer;
    response->body_size = total_body_size;

    /* Cleanup */
    WINHTTP$WinHttpCloseHandle(request_handle);
    MSVCRT$free(wide_host);
    MSVCRT$free(wide_path);
    MSVCRT$free(header_buffer);

    return TRUE;
}

static const LPWSTR HttpMethodToWideString(HttpMethod method) {
    /* Switch statement can generate a fail here :(
    See: https://tradecraftgarden.org/docs.html - Avoiding Common PIC-falls */
    
    if (method == HTTP_METHOD_GET) {
        return L"GET";
    } else if (method == HTTP_METHOD_POST) {
        return L"POST";
    } else if (method == HTTP_METHOD_PUT) {
        return L"PUT";
    } else if (method == HTTP_METHOD_DELETE) {
        return L"DELETE";
    } else if (method == HTTP_METHOD_HEAD) {
        return L"HEAD";
    } else if (method == HTTP_METHOD_PATCH) {
        return L"PATCH";
    } else {
        return L"UNKNOWN";
    }
}

static LPWSTR HttpUtf8ToWide(const char *utf8_string) {
    if (!utf8_string) {
        return NULL;
    }

    /* Calculate required buffer size */
    int wide_len = KERNELBASE$MultiByteToWideChar(CP_UTF8, 0, utf8_string, -1, NULL, 0);
    if (wide_len == 0) {
        return NULL;
    }

    /* Allocate buffer */
    LPWSTR wide_string = (LPWSTR)MSVCRT$malloc(wide_len * sizeof(WCHAR));
    if (!wide_string) {
        return NULL;
    }

    /* Convert */
    if (KERNELBASE$MultiByteToWideChar(CP_UTF8, 0, utf8_string, -1, wide_string, wide_len) == 0) {
        MSVCRT$free(wide_string);
        return NULL;
    }

    return wide_string;
}

static char* HttpWideToUtf8(LPWSTR wide_string) {
    if (!wide_string) {
        return NULL;
    }

    /* Calculate required buffer size */
    int utf8_len = KERNELBASE$WideCharToMultiByte(CP_UTF8, 0, wide_string, -1, NULL, 0, NULL, NULL);
    if (utf8_len == 0) {
        return NULL;
    }

    /* Allocate buffer */
    char *utf8_string = (char*)MSVCRT$malloc(utf8_len);
    if (!utf8_string) {
        return NULL;
    }

    /* Convert */
    if (KERNELBASE$WideCharToMultiByte(CP_UTF8, 0, wide_string, -1, utf8_string, utf8_len, NULL, NULL) == 0) {
        MSVCRT$free(utf8_string);
        return NULL;
    }

    return utf8_string;
}

