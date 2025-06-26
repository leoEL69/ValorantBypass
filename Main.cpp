#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <sstream>


typedef NTSTATUS(WINAPI* pNtSuspendProcess)(HANDLE);
pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSuspendProcess");


bool enableDebugPrivilege() {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return result && GetLastError() == ERROR_SUCCESS;
}

void stopVanguardService() {
    system("sc stop vgc > nul");
    system("sc config vgc start= demand > nul");
    std::cout << "[SUCCESS] VGC service stopped and set to manual.\n";
}

bool isVanguardRunning() {
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE svc = OpenService(scm, L"vgc", SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    BOOL result = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return result && (ssp.dwCurrentState == SERVICE_RUNNING || ssp.dwCurrentState == SERVICE_START_PENDING);
}

bool isProcessRunning(const std::wstring& processName) {
    PROCESSENTRY32W entry; entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                found = true; break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

void waitForInjectionWindow(int seconds) {
    MessageBoxW(NULL, L"Vanguard desprotegido!\n\nAperte OK e injete seu cheat agora.", L"Momento de Injeção", MB_OK | MB_ICONINFORMATION);
    for (int i = seconds; i > 0; --i) {
        std::cout << "[WAIT] Injeção recomendada em: " << i << "s...\r";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "\n[TIMEOUT] Janela de injeção encerrada. Continuando...\n";
}

void freezeTPMPopupProtection() {
    const std::wstring dns = L"svchost.exe";
    PROCESSENTRY32W entry; entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, dns.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, entry.th32ProcessID);
                if (hProcess) {
                    WCHAR path[MAX_PATH]; DWORD len = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, path, &len)) {
                        std::wstring full(path);
                        if (full.find(L"dnscache") != std::wstring::npos) {
                            std::wcout << L"[INFO] Congelando dnscache (PID: " << entry.th32ProcessID << L")\n";
                            NtSuspendProcess(hProcess);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void monitorAndSuspendVGM() {
    const std::wstring target = L"vgm.exe";
    std::wcout << L"[INFO] Monitorando e suspendendo " << target << L"...\n";
    while (true) {
        PROCESSENTRY32W entry; entry.dwSize = sizeof(entry);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        bool found = false;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, target.c_str()) == 0) {
                    found = true;
                    DWORD pid = entry.th32ProcessID;
                    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    THREADENTRY32 te32; te32.dwSize = sizeof(te32);
                    if (Thread32First(hThreadSnap, &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == pid) {
                                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                                if (hThread) { SuspendThread(hThread); CloseHandle(hThread); }
                            }
                        } while (Thread32Next(hThreadSnap, &te32));
                    }
                    CloseHandle(hThreadSnap);
                    std::wcout << L"[ACTION] Processo " << target << L" suspenso (PID: " << pid << L")\n";
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
}


// Verifica permissões de administrador e habilita privilégio de debug
bool isAdmin() {
    HANDLE token; TOKEN_ELEVATION elev; DWORD sz;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz)) {
            CloseHandle(token);
            return elev.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return false;
}

// Suspende apenas o processo de svchost.exe com tpmcore.dll carregada
bool processHasDLL(DWORD pid, const std::wstring& dll) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    HMODULE mods[1024]; DWORD cb;
    bool ok = false;
    if (EnumProcessModules(h, mods, sizeof(mods), &cb)) {
        for (unsigned i = 0; i < cb / sizeof(HMODULE); ++i) {
            wchar_t buf[MAX_PATH];
            if (GetModuleFileNameExW(h, mods[i], buf, MAX_PATH) && wcsstr(buf, dll.c_str())) {
                ok = true; break;
            }
        }
    }
    CloseHandle(h);
    return ok;
}

void bypassTPMPopup() {
    const std::wstring proc = L"svchost.exe";
    const std::wstring dll = L"tpmcore.dll";

    std::wcout << L"[BYPASS] Buscando svchost com '" << dll << L"'...\n";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W e; e.dwSize = sizeof(e);
    if (Process32FirstW(snap, &e)) {
        do {
            if (_wcsicmp(e.szExeFile, proc.c_str()) == 0) {
                if (processHasDLL(e.th32ProcessID, dll)) {
                    std::wcout << L"[FOUND] PID " << e.th32ProcessID << L", suspend via pssuspend\n";
                    std::wstringstream cmd; cmd << L"pssuspend.exe -accepteula " << e.th32ProcessID;
                    _wsystem(cmd.str().c_str());
                    break;
                }
            }
        } while (Process32NextW(snap, &e));
    }
    CloseHandle(snap);
}



int main() {
    MessageBoxW(NULL, L"Aperte OK quando o jogo estiver aberto", L"Aguardando Jogo", MB_ICONINFORMATION | MB_OK);
    std::wcout << L"[INFO] Aguardando VALORANT...\n";
    while (!isProcessRunning(L"VALORANT-Win64-Shipping.exe")) std::this_thread::sleep_for(std::chrono::seconds(1));
    std::wcout << L"[SUCCESS] Jogo detectado!\n";

    if (!isAdmin()) { std::cerr << "[ERROR] Rode como administrador!\n"; return 1; }
    if (!enableDebugPrivilege()) std::cerr << "[WARN] Debug privilege falhou\n";

    stopVanguardService();
    while (isVanguardRunning()) std::this_thread::sleep_for(std::chrono::milliseconds(500));

    waitForInjectionWindow(20);
    bypassTPMPopup();

    monitorAndSuspendVGM();
    return 0;
}