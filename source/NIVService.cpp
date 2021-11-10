#include "DataIntegrity.h"
#include "ModuleMgmt.h"
#include "NIVService.h"
#include "NTAPILoader.h"
#include <ctime>


#if _DEBUG
#include <stdio.h>
#endif

// Static definitions
NIVNotifyFunc     NIV_NotifyCallback    = nullptr;
NIVKeepAliveFunc  NIV_KeepAliveCallback = nullptr;
std::future<void> NIV_ThreadFix;

// --------------------------------------------------------------------------------------
// Function: Initialize
// Notes: None.
// --------------------------------------------------------------------------------------
bool NIV_Initialize(NIVNotifyFunc pFunc)
{
  if (nullptr == NIV_NotifyCallback)
  {
    NIV_NotifyCallback = pFunc;
  }

  return NTAPILoader::NTAPI_Load();
}

// --------------------------------------------------------------------------------------
// Function: CRC32Init
// Notes: None.
// --------------------------------------------------------------------------------------
bool NIV_CRC32Init(NIVTypes::CRCEnum id,
                   const char* moduleName,
                   const char* section)
{
  uint32_t nBytes = 0;
  void* address = nullptr;

  // CRC_MAIN_ID is reserved for parent module .TEXT 
  if (NIVTypes::CRC_MAIN_ID == id)
  {
    ModuleMgmt::QuerySection(".text", address, nBytes);
  }

  // NIV_MAIN_ID is reserved for NIVService .TEXT
  else if (NIVTypes::NIV_MAIN_ID == id)
  {
    ModuleMgmt::QueryModuleSection(".text", "NIVSvc.dll", address, nBytes);
  }
  
  // All other ids are specified by the user.
  else
  {
    if (nullptr == moduleName)
    {
      ModuleMgmt::QuerySection(section, address, nBytes);
    }
    else
    {
      ModuleMgmt::QueryModuleSection(section, moduleName, address, nBytes);
    }
  }

  return DataIntegrity::Instance()->CRC32Init(address, nBytes, id);
}

// --------------------------------------------------------------------------------------
// Function: CRC32Init
// Notes: None.
// --------------------------------------------------------------------------------------
bool NIV_CRC32Register(NIVTypes::CRCEnum id,
                       void* address,
                       size_t nBytes,
                       uint32_t crc32)
{
  return DataIntegrity::Instance()->CRC32Register(address, nBytes, id, crc32);
}

// --------------------------------------------------------------------------------------
// Function: CRC32Validate
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_CRC32Validate(NIVTypes::CRCEnum id)
{
  DataIntegrity::Instance()->CRC32Validate(id);
}

// --------------------------------------------------------------------------------------
// Function: BeginSession
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_BeginSession(NIVKeepAliveFunc pFunc, uint32_t frequencyMs)
{
  if (nullptr == NIV_KeepAliveCallback)
  {
    NIV_KeepAliveCallback = pFunc;
    NIV_ThreadFix = std::async(std::launch::async, NIV_SessionTracker, frequencyMs);
  }
}

// --------------------------------------------------------------------------------------
// Function: BuildSessionResponse
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_BuildSessionResponse(NIVTypes::SessionMessage* query,
                              NIVTypes::SessionMessage& msg)
{
  std::clock_t currTime = std::clock() / (CLOCKS_PER_SEC / 1000);

  msg.timeMs = currTime;
  msg.queryResponse = 1;
  msg.signature = query->signature + 1;
  msg.checksum = NIV_Checksum32(reinterpret_cast<uint8_t*>(&msg),
                                sizeof(NIVTypes::SessionMessage) - sizeof(uint32_t));
}

// --------------------------------------------------------------------------------------
// Function: ExceptionHandler
// Notes: None.
// --------------------------------------------------------------------------------------
BOOL SEHDebuggerPresent = TRUE;
EXCEPTION_DISPOSITION ExceptionHandler(PEXCEPTION_RECORD ExceptionRecord,
                                       PVOID  EstablisherFrame,
                                       PCONTEXT ContextRecord,
                                       PVOID DispatcherContext)
{
  ContextRecord->Eip += 1;
  SEHDebuggerPresent = FALSE;
  return ExceptionContinueExecution;
} 

// --------------------------------------------------------------------------------------
// Function: NIV_CheckForDebugger
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_CheckForDebugger()
{
  // Check PEB for debugger presence
  PEB peb;
  ModuleMgmt::GetProcessPEB(&peb);
  if ((0 != peb.BeingDebugged) ||
      (TRUE == IsDebuggerPresent()))
  {
    NIV_Notify(NIVTypes::TAMPER_DETECTED,
               NIVTypes::DBG_DETECTION,
               0); // PEB detection
  }

  BOOL isDebuggerPresent = FALSE;
  if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent))
  {
    if (TRUE == isDebuggerPresent)
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::DBG_DETECTION,
                 1); // Remote debugger detection
    }
  }

  // Next check context flags for debugger
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  HANDLE thisThread = GetCurrentThread();
  if (0 <= _NtGetContextThread(thisThread, &ctx))
  {
    if ((ctx.Dr0) || 
        (ctx.Dr1) || 
        (ctx.Dr2) || 
        (ctx.Dr3))
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::DBG_DETECTION,
                 2); // HW detection
    }
  }

  // Software breakpoints should trip the CRC validation.
  // One last debugger detection method.
  __asm
  {
    push ExceptionHandler
    push dword ptr fs:[0x00000000]
    mov dword ptr fs:[0x00000000], esp
    int 3
    mov eax, [esp]
    mov dword ptr fs:[0x00000000], eax
    add esp, 8 
  }

  if (TRUE == SEHDebuggerPresent)
  {
    NIV_Notify(NIVTypes::TAMPER_DETECTED,
                NIVTypes::DBG_DETECTION,
                3); // Exception Handler detected
  }
}

// --------------------------------------------------------------------------------------
// Function: NIV_InstallLibraryFilter
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_InstallLibraryFilter()
{
  ModuleMgmt::LdrLoadDll_InstallHook();
}

// --------------------------------------------------------------------------------------
// Function: NIV_SetLibraryFilterBehavior
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_SetLibraryFilterBehavior(NIVTypes::BehaviorType type)
{
  ModuleMgmt::SetLibraryFilterBehavior(type);
}

// --------------------------------------------------------------------------------------
// Function: NIV_AddLibraryToFilter
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_AddLibraryToFilter(const char* lib)
{
  ModuleMgmt::AddLibraryToFilter(lib);
}

// --------------------------------------------------------------------------------------
// Function: Notify
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_Notify(NIVTypes::NotifyLevel level,
                NIVTypes::NotifyType  type,
                uintptr_t p1,
                uintptr_t p2,
                uintptr_t p3,
                uintptr_t p4)
{
  NIVTypes::NIVNotification notification =
  {
    level,
    type,
    p1,
    p2,
    p3,
    p4
  };

  NIV_NotifyCallback(&notification);
}

// --------------------------------------------------------------------------------------
// Function: SelfDestruct
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_SelfDestruct()
{
  // Essentially invoking an invalid function..
  reinterpret_cast<void(*)()>(0)();
}

// --------------------------------------------------------------------------------------
// Function: Checksum32
// Notes: None.
// --------------------------------------------------------------------------------------
uint32_t NIV_Checksum32(uint8_t* buf, uint32_t nBytes)
{
  uint32_t csum = 0;
  for (size_t i = 0; i < nBytes; ++i)
  {
    csum += buf[i];
    if (0 == csum)
    {
      ++csum;
    }
  }

  return ~csum;
}

// --------------------------------------------------------------------------------------
// Function: SessionTracker
// Notes: None.
// --------------------------------------------------------------------------------------
void NIV_SessionTracker(uint32_t frequencyMs)
{
  static uint32_t counter = 0;

  uint32_t waitTime = frequencyMs;
  while (true)
  {
    if ((0 == waitTime) ||
        (NIVTypes::MAX_SESSION_FREQ < frequencyMs))
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::COMMUNICATION,
                 1,          // Invalid Wait Time
                 waitTime);  // Wait Time
    }
    else
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(waitTime));
    }
    
    // Send a session query message.
    NIVTypes::SessionMessage query;
    std::clock_t currTime = std::clock() / (CLOCKS_PER_SEC / 1000);

    query.timeMs = currTime;
    query.queryResponse = 0;
    query.signature = ++counter;
    query.checksum = NIV_Checksum32(reinterpret_cast<uint8_t*>(&query),
                                    sizeof(NIVTypes::SessionMessage) - 
                                      sizeof(uint32_t));

#if _DEBUG
    printf("%s: Time=%d QUERY Signature=%d Checksum=%08x\n",
           __PRETTY_FUNCTION__,
           query.timeMs,
           query.signature,
           query.checksum);
#endif

    NIVTypes::SessionMessage response;
    NIV_KeepAliveCallback(&query, response);

#if _DEBUG
    printf("%s: Time=%d RESPONSE Signature=%d Checksum=%08x\n",
           __PRETTY_FUNCTION__,
           response.timeMs,
           response.signature,
           response.checksum);
#endif

    // Validate checksum
    if (response.checksum !=
        NIV_Checksum32(reinterpret_cast<uint8_t*>(&response),
                       sizeof(NIVTypes::SessionMessage) - sizeof(uint32_t)))
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::COMMUNICATION,
                 2,          // Invalid checksum
                 response.checksum);  // Wait Time
      continue;
    }

    // Validate queryResponse
    if (1 != response.queryResponse)
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::COMMUNICATION,
                 3);        // Invalid query/response
      continue;
    }

    // Validate counter
    if (1 != (response.signature - query.signature))
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::COMMUNICATION,
                 4);        // Invalid signature
      continue;
    }

    // Validate time
    uint32_t elapsedTime = response.timeMs - query.timeMs;
    if (50 < elapsedTime)
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED,
                 NIVTypes::COMMUNICATION,
                 5,         // Invalid response time
                 elapsedTime);
      continue;
    }
  }
}