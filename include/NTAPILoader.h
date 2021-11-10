#pragma once
#include <Windows.h>
#include <winternl.h>



// --------------------------------------------------------------------------------------
// The following Windows API functions are utilized by NIVSvc.
// --------------------------------------------------------------------------------------
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)
  (HANDLE           ProcHandle,
   PROCESSINFOCLASS ProcInfoClass,
   PVOID            ProcInfo,
   ULONG            ProcInfoLen,
   PULONG           returnLen OPTIONAL);

typedef NTSTATUS(NTAPI* pfnLdrLoadDll)
  (PWCHAR PathToFile OPTIONAL,
   ULONG             Flags,
   PUNICODE_STRING   ModuleFileName,
   PHANDLE           ModuleHandle);

typedef NTSTATUS(NTAPI* pfnNtGetContextThread)
  (HANDLE            ThreadHandle,
   PCONTEXT          pContext);

extern pfnNtQueryInformationProcess _NtQueryInformationProcess;
extern pfnLdrLoadDll _LdrLoadDll;
extern pfnNtGetContextThread _NtGetContextThread;

// --------------------------------------------------------------------------------------
//  Initializtion 
// --------------------------------------------------------------------------------------
class NTAPILoader
{
public:
  
  static bool NTAPI_Load();

private:

  static bool NTAPI_LOAD;
};