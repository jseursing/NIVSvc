#pragma once
#include "ModuleMgmt.h"
#include "NIVTypes.h"
#include <future>

// Function Callbacks
typedef void(*NIVNotifyFunc)(NIVTypes::NIVNotification*);

// NOTE: The following call back defined by the client should
//       construct a response using BuildSessionResponse.
typedef void(*NIVKeepAliveFunc)(NIVTypes::SessionMessage*, 
                                NIVTypes::SessionMessage&);

#if NIV_DLL
#define NIV_API extern "C" __declspec(dllexport)
#else
#define NIV_API extern "C" __declspec(dllimport)
#endif

// Class definition
NIV_API bool NIV_Initialize(NIVNotifyFunc pFunc);

// Data Integrity
NIV_API bool NIV_CRC32Init(NIVTypes::CRCEnum id,
                           const char* moduleName, 
                           const char* section);
NIV_API bool NIV_CRC32Register(NIVTypes::CRCEnum id,
                               void* address,
                               size_t nBytes,
                               uint32_t crc32 = 0);
NIV_API void NIV_CRC32Validate(NIVTypes::CRCEnum id);

// Debugger Check
NIV_API void NIV_CheckForDebugger();

// Library Injection check
NIV_API void NIV_InstallLibraryFilter();
NIV_API void NIV_SetLibraryFilterBehavior(NIVTypes::BehaviorType type);
NIV_API void NIV_AddLibraryToFilter(const char* lib);

// Session Management
NIV_API void NIV_BeginSession(NIVKeepAliveFunc pFunc, uint32_t frequencyMs);
NIV_API void NIV_BuildSessionResponse(NIVTypes::SessionMessage* query,
                                      NIVTypes::SessionMessage& msg);

// Notifications
NIV_API void NIV_Notify(NIVTypes::NotifyLevel level,
                        NIVTypes::NotifyType  type,
                        uintptr_t p1 = 0,
                        uintptr_t p2 = 0, 
                        uintptr_t p3 = 0, 
                        uintptr_t p4 = 0);

// Destruction!
NIV_API void NIV_SelfDestruct();

// Support functions
NIV_API uint32_t NIV_Checksum32(uint8_t* buf, uint32_t nBytes);
NIV_API void NIV_SessionTracker(uint32_t frequencyMs);