#pragma once
#include "NIVTypes.h"
#include "NTAPILoader.h"
#include <stdint.h>
#include <string>
#include <vector>

// Forward declarations
class ModuleMgmt
{
public:

  static void GetProcessPEB(void* peb, uint32_t offset = 0);
  static void QuerySection(const char* section, 
                           void*& address, 
                           uint32_t& nBytes);
  static void QueryModuleSection(const char* section, 
                                 const char* libPath, 
                                 void*& address, 
                                 uint32_t& nBytes);
  static void SetLibraryFilterBehavior(NIVTypes::BehaviorType type);
  static void AddLibraryToFilter(const char* lib);
  static void LdrLoadDll_InstallHook();
  static void LdrLoadDll_UninstallHook();

private:
  static void GetSectionMemRegion(const char* section, 
                                  void* imageBase, 
                                  void*& address, 
                                  uint32_t& nBytes);

  static NTSTATUS __stdcall LdrLoadDll_(PWCHAR PathToFile OPTIONAL,
                                        ULONG             Flags,
                                        PUNICODE_STRING   ModuleFileName,
                                        PHANDLE           ModuleHandle);

  static size_t LdrLoadDllByteLen;
  static uint8_t* LdrLoadDllOrigBytes;
  static NIVTypes::BehaviorType FilterBehavior;
  static std::vector<std::string> LibraryList;
};