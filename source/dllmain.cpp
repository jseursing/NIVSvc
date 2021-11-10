#include "NIVService.h"
#if _DEBUG
#include <windows.h>
#endif

// --------------------------------------------------------------------------------------
// Function: DllMain
// Notes: None
// --------------------------------------------------------------------------------------
int __stdcall DllMain(HMODULE hModule, 
                      unsigned long ul_reason_for_call, 
                      void* lpReserved)
{
  switch (ul_reason_for_call)
  {
    case DLL_PROCESS_ATTACH:
    {
#if _DEBUG
      AllocConsole();
#endif
    }
    break;
    case DLL_PROCESS_DETACH:
    {

    }
    break;
  }

  return TRUE;
}

