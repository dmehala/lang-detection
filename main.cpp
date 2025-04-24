#include <Windows.h>
#include <filesystem>
#include <iostream>

static bool CreateRemoteThread_Type1(LPCSTR DllPath, HANDLE hProcess) {

  LPVOID LoadLibAddr =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

  if (!LoadLibAddr) {
    printf("Could note locate real address of LoadLibraryA!\n");
    printf("LastError : 0X%x\n", GetLastError());
    system("PAUSE");
    return false;
  }

  printf("LoadLibraryA is located at real address: 0X%p\n",
         (void *)LoadLibAddr);

  LPVOID pDllPath =
      VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT, PAGE_READWRITE);

  if (!pDllPath) {
    printf("Could not allocate Memory in target process\n");
    printf("LastError : 0X%x\n", GetLastError());
    system("PAUSE");
    return false;
  }

  printf("Dll path memory allocated at: 0X%p\n", (void *)pDllPath);

  BOOL Written = WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath,
                                    strlen(DllPath), NULL);

  if (!Written) {
    printf("Could not write into the allocated memory\n");
    printf("LastError : 0X%x\n", GetLastError());
    system("PAUSE");
    return false;
  }

  printf("Dll path memory was written at address : 0x%p\n", (void *)pDllPath);

  HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
                                      (LPTHREAD_START_ROUTINE)LoadLibAddr,
                                      pDllPath, 0, NULL);

  if (!hThread) {
    printf("Could not open Thread with CreatRemoteThread API\n");
    printf("LastError : 0X%x\n", GetLastError());
    system("PAUSE");
    return false;
  }

  printf("Thread started with CreateRemoteThread\n");

  WaitForSingleObject(hThread, INFINITE);

  if (VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE)) {
    // VirtualFreeEx(hProc, reinterpret_cast<int*>(pDllPath) + 0X010000, 0,
    // MEM_RELEASE);
    printf("Memory was freed in target process\n");
    Sleep(1000);
  }

  CloseHandle(hThread);

  return true;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <DLL> <PID>";
    return 1;
  }

  const auto dllpath = argv[1];
  const DWORD pid = atoi(argv[2]);

  if (!std::filesystem::exists(dllpath)) {
    std::cerr << "dll \"" << dllpath << "\" does not exists." << std::endl;
    return 1;
  }

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess) {
    std::cerr << "Could not open Process for PID " << pid << std::endl;
    std::cerr << "LastError : " << GetLastError() << std::endl;
    return 1;
  }

  if (!CreateRemoteThread_Type1(dllpath, hProcess)) {
    std::cerr << "Failed to inject the dll" << std::endl;
  }
  return 0;
}
