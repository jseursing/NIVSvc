#include "..\include\NIVService.h"
#include <Windows.h>

void OnTamperDetected(NIVTypes::NIVNotification* notification)
{
  printf("[TAMPER DETECTED]\n"
         "Level=%s Module=%s P1=%08X P2=%08X P3=%08X P4=%08X\n\n",
         NIVTypes::NotifyString(notification->level),
         NIVTypes::TypeString(notification->notifyType),
         notification->parameters[0],
         notification->parameters[1], 
         notification->parameters[2], 
         notification->parameters[3]);
}

void KeepAliveCallback(NIVTypes::SessionMessage* query,
                       NIVTypes::SessionMessage& response)
{
  NIV_BuildSessionResponse(query, response);
}

int main(int argc, char* argv[])
{
  // Perform initialization
  HMODULE hm = LoadLibraryA(".\\NIVSvc.dll");

  NIV_Initialize(OnTamperDetected);
  NIV_BeginSession(KeepAliveCallback, 10000);
  
  // Register library sniffer
  NIV_InstallLibraryFilter();
  NIV_SetLibraryFilterBehavior(NIVTypes::LIB_BLACKLIST);
  NIV_AddLibraryToFilter("GITerminal.dll");

  // Register self and NISvc CRC
  NIV_CRC32Init(NIVTypes::CRC_MAIN_ID, nullptr, nullptr);
  NIV_CRC32Init(NIVTypes::NIV_MAIN_ID, nullptr, nullptr);

  // CRC check LdrLoadDll
  HMODULE hModule = GetModuleHandleA("ntdll.dll");
  void* ldrLoadDllFunc = GetProcAddress(hModule, "LdrLoadDll");
  NIV_CRC32Register(NIVTypes::CRC_ID_0, ldrLoadDllFunc, 8);

  while (true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    NIV_CRC32Validate(NIVTypes::CRC_MAIN_ID);
    NIV_CRC32Validate(NIVTypes::NIV_MAIN_ID);
    NIV_CRC32Validate(NIVTypes::CRC_ID_0);
    NIV_CheckForDebugger();
  }
}

