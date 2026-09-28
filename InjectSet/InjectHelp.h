#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);

#pragma comment(lib, "ntdll.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)
#endif

static void PrintLastError(const char* fn)
{
	DWORD err = GetLastError();
	LPSTR buf = NULL;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
	printf("[!] %s Failed With Error: %lu\n", fn, err);
	if (buf) LocalFree(buf);
}

static BOOL ParseU64(const char* s, uint64_t* out)
{
	if (!s || !*s)
		return FALSE;
	char* end = NULL;
	unsigned long long v = _strtoui64(s, &end, 0);
	if (end == s || *end != '\0')
		return FALSE;
	*out = v;
	return TRUE;
}

static bool FindPatternInRemoteProcess(
    HANDLE hProcess,
    const uint8_t* pattern,
    size_t patternSize,
    uintptr_t* outAddr)
{
    SYSTEM_INFO sysInfo = { 0 };
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    uint8_t* buffer = NULL;
    size_t bufferCap = 0;
    uintptr_t address, maxAddr;
    bool found = false;

    if (!pattern || patternSize == 0 || !outAddr)
        return false;

    GetNativeSystemInfo(&sysInfo);

    address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    while (address < maxAddr) {
        bool isPrivate, isCommitted, isReadable, isGuarded;
        // 2. Query the next region.
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            // Cannot query here — advance one page to avoid infinite loop.
            address += sysInfo.dwPageSize;
            continue;
        }
        // 3. Filter: only private, committed, readable (not guarded) memory.
        isPrivate = (mbi.Type == MEM_PRIVATE);
        isCommitted = (mbi.State == MEM_COMMIT);
        isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        isGuarded = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;

        if (isPrivate && isCommitted && isReadable && !isGuarded) {
            SIZE_T regionSize = mbi.RegionSize;

            // Skip regions smaller than the pattern.
            if (regionSize >= patternSize) {
                SIZE_T bytesRead = 0;

                // Grow the buffer only when needed (replaces vector::resize).
                if (regionSize > bufferCap) {
                    uint8_t* newBuf = (uint8_t*)realloc(buffer, regionSize);
                    if (!newBuf)
                        break;  // out of memory — stop scanning
                    buffer = newBuf;
                    bufferCap = regionSize;
                }

                // 4. Read the whole region in one shot.
                if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                    buffer, regionSize, &bytesRead)
                    && bytesRead >= patternSize)
                {
                    // 5. Search inside this chunk.
                    size_t limit = bytesRead - patternSize;
                    size_t i;
                    for (i = 0; i <= limit; ++i) {
                        if (memcmp(buffer + i, pattern, patternSize) == 0) {
                            *outAddr = (uintptr_t)mbi.BaseAddress + i;
                            found = true;
                            break;
                        }
                    }
                    if (found)
                        break;
                }
                // If ReadProcessMemory fails partially, we still advance below.
            }
        }

        // Advance to next region.
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    free(buffer);
    return found;
}

// ---------- main thread discovery ----------
// Picks the thread whose Win32 start address falls inside the main module
// image. Falls back to the first thread of the process.
static DWORD GetMainThreadId(DWORD pid) {
    uintptr_t imageBase = 0, imageEnd = 0;
    DWORD best = 0, firstAny = 0;
    HANDLE snap;
    THREADENTRY32 te = { 0 };

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = { 0 };
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            imageBase = (uintptr_t)me.modBaseAddr;
            imageEnd = imageBase + me.modBaseSize;
        }
        CloseHandle(snap);
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE hT;
            void* startAddr = NULL;

            if (te.th32OwnerProcessID != pid) continue;
            if (!firstAny) firstAny = te.th32ThreadID;

            hT = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!hT) continue;

            NtQueryInformationThread(hT,
                (THREADINFOCLASS)ThreadQuerySetWin32StartAddress,
                &startAddr, sizeof(startAddr), NULL);
            CloseHandle(hT);

            if (startAddr && imageBase && imageEnd &&
                (uintptr_t)startAddr >= imageBase &&
                (uintptr_t)startAddr < imageEnd) {
                best = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return best ? best : firstAny;
}

static BOOL HijackThreadRip(DWORD tid, uint64_t newRip)
{
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!hThread)
    {
        PrintLastError("OpenThread");
        return FALSE;
    }

    if (SuspendThread(hThread) == (DWORD)-1)
    {
        PrintLastError("SuspendThread");
        return FALSE;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx))
    {
        PrintLastError("GetThreadContext");
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    printf("[+] Thread %lu: old RIP = 0x%llX, RSP =0x%llX\n", tid, (unsigned long long)ctx.Rip, (unsigned long long) ctx.Rsp);

    ctx.Rip = newRip;

    NTSTATUS status = NtSetContextThread(hThread, &ctx);
    if (status != 0)
    {
        printf("[!] NtSetContextThread Failed. NTSTATUS = 0x%08lX\n", (unsigned long)status);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] Thread %lu: new RIP = 0x%llX\n", tid, (unsigned long long)newRip);

    if (ResumeThread(hThread) == (DWORD)-1) PrintLastError("ResumeThread");
    else printf("[+] Thread %lu Resumed\n", tid);

    CloseHandle(hThread);
    return TRUE;

}