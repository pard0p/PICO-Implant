#ifndef LIBWINHTTP_HTTP_H
#define LIBWINHTTP_HTTP_H

#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include <winhttp.h>

/**
 * LibWinHttp - Simple WinHTTP wrapper library
 *
 * A lightweight abstraction over Microsoft's WinHTTP API that hides
 * the complexity of session/connection/request management and provides
 * straightforward HTTP operations.
 */

/** ============================================================================
 * Type Definitions
 * ============================================================================ */

/**
 * HTTP client structure - contains configuration and state.
 * Users can modify response_timeout_ms and user_agent directly.
 */
typedef struct {
    HINTERNET session_handle;
    HINTERNET connection_handle;
    DWORD https_enabled;
    DWORD response_timeout_ms;
    char user_agent[256];
} HttpHandle;

/**
 * HTTP method enumeration.
 */
typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_PATCH
} HttpMethod;

/**
 * HTTP response structure - contains response data and metadata.
 */
typedef struct {
    DWORD status_code;
    char *body;
    SIZE_T body_size;
    char *content_type;
} HttpResponse;

/**
 * HTTP header for custom headers in requests.
 */
typedef struct {
    char *name;
    char *value;
} HttpHeader;

/**
 * HTTP headers collection - groups headers array and count.
 */
typedef struct {
    HttpHeader *headers;
    DWORD count;
} HttpHeaders;

/**
 * HTTP request body - groups body data and size.
 */
typedef struct {
    const BYTE *data;
    SIZE_T size;
} HttpBody;

/**
 * HTTP URI - groups host, port and path.
 */
typedef struct {
    const char *host;
    INTERNET_PORT port;
    const char *path;
} HttpURI;

/** ============================================================================
 * Core Functions
 * ============================================================================ */

/**
 * Create and initialize a new HTTP client handle.
 * https_enabled: 1 to enable HTTPS support (default), 0 to disable.
 * Returns a pointer to a new HttpHandle structure, or NULL on failure.
 * The user owns the returned handle and must free it with HttpDestroy().
 */
HttpHandle* HttpInit(DWORD https_enabled);

/**
 * Destroy and cleanup an HTTP client handle.
 * Closes all connections and frees all resources associated with the handle.
 * Must be called for every handle created with HttpInit().
 */
void HttpDestroy(HttpHandle *handle);

/** ============================================================================
 * HTTP Requests
 * ============================================================================ */

/**
 * Perform an HTTP request.
 * handle: HTTP client handle from HttpInit().
 * method: HTTP method to use (GET, POST, PUT, DELETE, HEAD, PATCH).
 * uri: URI containing host, port and path.
 * headers: Headers collection (can be NULL for no headers).
 * body: Request body (can be NULL for GET/HEAD/DELETE).
 * response: Pointer to HttpResponse structure (will be populated).
 * Returns TRUE on success, FALSE on failure.
 */
BOOL HttpRequest(
    HttpHandle *handle,
    HttpMethod method,
    const HttpURI *uri,
    const HttpHeaders *headers,
    const HttpBody *body,
    HttpResponse *response
);

#endif /* LIBWINHTTP_HTTP_H */