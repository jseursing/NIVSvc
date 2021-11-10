#include "NTAPILoader.h"

pfnNtQueryInformationProcess _NtQueryInformationProcess = nullptr;
pfnLdrLoadDll _LdrLoadDll                               = nullptr;
pfnNtGetContextThread _NtGetContextThread               = nullptr;

bool NTAPILoader::NTAPI_LOAD = false;

// --------------------------------------------------------------------------------------
// Function: NTAPI_Load
// Notes: None.
// --------------------------------------------------------------------------------------
bool NTAPILoader::NTAPI_Load()
{
  if (false == NTAPI_LOAD)
  {
    HMODULE ntModule = GetModuleHandleA("ntdll.dll");
    if (nullptr == ntModule)
    {
      return false;
    }

    _NtQueryInformationProcess = reinterpret_cast<pfnNtQueryInformationProcess>
                                 (GetProcAddress(ntModule, "NtQueryInformationProcess"));
    _LdrLoadDll = reinterpret_cast<pfnLdrLoadDll>(GetProcAddress(ntModule, "LdrLoadDll"));
    _NtGetContextThread = reinterpret_cast<pfnNtGetContextThread>
                          (GetProcAddress(ntModule, "NtGetContextThread"));

    NTAPI_LOAD = ((nullptr != _NtQueryInformationProcess) &&
                  (nullptr != _LdrLoadDll) &&
                  (nullptr != _NtGetContextThread));
  }
  
  return NTAPI_LOAD;
}
