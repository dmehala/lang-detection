#include <Windows.h>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <psapi.h>
#include <string_view>

void close() {
  typedef NTSTATUS(WINAPI * pNtTerminateProcess)(IN NTSTATUS ExitStatus);
  auto pFuncNtTerminateProcess = (pNtTerminateProcess)GetProcAddress(
      GetModuleHandle("ntdll.dll"), "NtTerminateProcess");
  pFuncNtTerminateProcess((NTSTATUS)0);
}

bool contains(std::string_view sv, std::string_view pattern) {
  return sv.find(pattern) != sv.npos;
}

bool try_python(HMODULE *hPython) {
  assert(hPython != nullptr);

  typedef const char *(*PyGetVersionFunc)();
  PyGetVersionFunc Py_GetVersion =
      (PyGetVersionFunc)GetProcAddress(*hPython, "Py_GetVersion");
  if (Py_GetVersion == nullptr)
    return false;

  auto v = Py_GetVersion();
  if (!v)
    return false;

  std::cout << "Found Python version: " << v << std::endl;
  return true;
}

bool try_dotnet(HMODULE *hDotnet) {
  assert(hDotnet != nullptr);

  typedef HRESULT (*GetCORVersionFunc)(LPWSTR, DWORD, DWORD *);
  GetCORVersionFunc GetCORVersion =
      (GetCORVersionFunc)GetProcAddress(*hDotnet, "GetCORVersion");
  if (GetCORVersion == nullptr)
    return false;

  char buffer[1024];
  DWORD n;
  HRESULT res = GetCORVersion((LPWSTR)buffer, 1024, &n);
  if (n <= 0)
    return false;

  std::string_view version{buffer, n};
  std::cout << "Found .NET version: " << version << std::endl;
  return true;
}

bool try_nodejs(HMODULE *hNodeJS) {
  assert(hNodeJS != nullptr);

  typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    const char *release;
  } napi_node_version;

  typedef char node_api_basic_env[512];
  typedef int (*napi_func)(node_api_basic_env env,
                           const napi_node_version **version);

  napi_func get_version =
      (napi_func)GetProcAddress(*hNodeJS, "napi_get_node_version");
  if (get_version == nullptr)
    return false;

  const napi_node_version *version;
  node_api_basic_env env;
  int res = get_version(env, &version);
  if (res != 0)
    return false;

  std::cout << "Found nodejs version: " << version->major << "."
            << version->minor << "." << version->patch << std::endl;
  return true;
}

bool try_php(HMODULE *hPhp) {
  assert(hPhp != nullptr);

  typedef const char *(*php_version_func)();
  php_version_func php_version =
      (php_version_func)GetProcAddress(*hPhp, "php_version");
  if (php_version == nullptr)
    return false;

  auto version = php_version();
  if (version == nullptr)
    return false;

  std::cout << "Found PHP version: " << version << std::endl;
  return true;
}

bool try_ruby(HMODULE *hRuby) {
  assert(hRuby != nullptr);

  const char *version = (const char *)GetProcAddress(*hRuby, "ruby_version");
  if (version == nullptr)
    return false;

  std::cout << "Found Ruby version: " << version << std::endl;
  return true;
}

void detect_runtime() {
  DWORD pid = GetCurrentProcessId();
  if (pid == 0)
    return;

  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
  if (hProcess == nullptr) {
    std::cout << "failed to open process " << pid << std::endl;
    return;
  }

  HMODULE hModule[1024];
  DWORD nModules;
  if (!EnumProcessModules(hProcess, hModule, 1024, &nModules)) {
    std::cerr << "failed to enum modules" << std::endl;
    return;
  }

  for (DWORD i = 0; i < nModules / sizeof(HMODULE); ++i) {
    char modname[MAX_PATH];
    if (!GetModuleFileName(hModule[i], modname, 1024)) {
      std::cout << "Failed to load module name" << std::endl;
      continue;
    }

    std::filesystem::path dllpath{modname};
    std::string dllname{dllpath.filename().generic_string()};
    std::string_view view{dllname};

    /*std::cout << "Found module: " << modname << ", dll: " << dllname*/
    /*          << std::endl;*/

    if (view.starts_with("python")) {
      std::cout << "Python detected!" << std::endl;
      if (try_python(&hModule[i]))
        return;
    } else if (view.starts_with("MSCOREE")) {
      std::cout << "Dotnet detected!" << std::endl;
      if (try_dotnet(&hModule[i]))
        return;
    } else if (view.starts_with("node.exe")) {
      std::cout << "NodeJS detected!" << std::endl;
      if (try_nodejs(&hModule[i]))
        return;
    } else if (contains(view, "php")) {
      std::cout << "PHP detected!" << std::endl;
      if (try_php(&hModule[i]))
        return;
    } else if (contains(view, "ruby")) {
      std::cout << "Ruby detected!" << std::endl;
      if (try_ruby(&hModule[i]))
        return;
    } else if (view == "java.dll" || view == "jvm.dll") {
      std::cout << "Java detected!" << std::endl;
    }
  }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {

  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    detect_runtime();
    close();
    break;

  case DLL_THREAD_ATTACH:
    break;

  case DLL_THREAD_DETACH:
    break;

  case DLL_PROCESS_DETACH:
    break;
  }

  return TRUE;
}
