#pragma once
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static char* ReadFromPipe(HANDLE hPipeRead, DWORD* outLen)
{
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    char* buffer;

    if (outLen) *outLen = 0;

    if (!PeekNamedPipe(hPipeRead, NULL, 0, NULL, &bytesAvailable, NULL) || bytesAvailable == 0) {
        return NULL;
    }

    buffer = (char*)calloc((size_t)bytesAvailable + 1, 1);
    if (!buffer) {
        return NULL;
    }

    if (ReadFile(hPipeRead, buffer, bytesAvailable, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        if (outLen) *outLen = bytesRead;
        return buffer;
    }

    free(buffer);
    return NULL;
}

/* Sends a text command to the child process. */
static bool WriteToPipe(HANDLE hPipeWrite, const char* command)
{
    DWORD bytesWritten = 0;
    return WriteFile(hPipeWrite, command, (DWORD)strlen(command), &bytesWritten, NULL) != FALSE;
}

/* Sends raw binary data to the child process. */
static bool WriteToPipeBin(HANDLE hPipeWrite, const BYTE* buff, DWORD size)
{
    DWORD bytesWritten = 0;
    return WriteFile(hPipeWrite, buff, size, &bytesWritten, NULL) != FALSE;
}