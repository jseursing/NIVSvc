#include "ModuleMgmt.h"
#include "NIVService.h"
#include <stdio.h>


size_t ModuleMgmt::LdrLoadDllByteLen                = 0;
uint8_t* ModuleMgmt::LdrLoadDllOrigBytes            = nullptr;
NIVTypes::BehaviorType ModuleMgmt::FilterBehavior   = NIVTypes::LIB_BLACKLIST;
std::vector<std::string> ModuleMgmt::LibraryList;

// --------------------------------------------------------------------------------------
// Function: GetProcessPEB
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::GetProcessPEB(void* peb, uint32_t offset)
{
  // Retrieve parent module base address
  PROCESS_BASIC_INFORMATION pbi;
  HANDLE pHandle = GetCurrentProcess();
  NTSTATUS status = _NtQueryInformationProcess(pHandle,
                                               ProcessBasicInformation,
                                               &pbi,
                                               sizeof(pbi),
                                               0);
  if (true == NT_SUCCESS(status))
  {
    void* address = reinterpret_cast<void*>
                    (reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + offset);
    memcpy(peb, address, sizeof(PEB));
  }
}

// --------------------------------------------------------------------------------------
// Function: QuerySection
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::QuerySection(const char* section, 
                              void*& address, 
                              uint32_t& nBytes)
{
  // Set initial values
  address = nullptr;
  nBytes  = 0;

  // Retrieve parent module base address
  PEB peb;
  GetProcessPEB(&peb);

  // Retrieve section information
  GetSectionMemRegion(section, peb.Reserved3[1], address, nBytes);
}

// --------------------------------------------------------------------------------------
// Function: QueryModuleSection
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::QueryModuleSection(const char* section, 
                                    const char* libPath, 
                                    void*& address, 
                                    uint32_t& nBytes)
{
  // Set initial values
  address = nullptr;
  nBytes  = 0;

  // Retrieve module address
  void* pModule = GetModuleHandleA(libPath);
  if (nullptr != pModule)
  {
    // Retrieve section information
    GetSectionMemRegion(section, pModule, address, nBytes);
  }
}

// --------------------------------------------------------------------------------------
// Function: SetLibraryFilterBehavior
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::SetLibraryFilterBehavior(NIVTypes::BehaviorType type)
{
  FilterBehavior = type;
}

// --------------------------------------------------------------------------------------
// Function: AddLibraryToFilter
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::AddLibraryToFilter(const char* lib)
{
  LibraryList.emplace_back(lib);
}

// --------------------------------------------------------------------------------------
// Function: LdrLoadDll_InstallHook
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::LdrLoadDll_InstallHook()
{
#if _WIN32 || _WIN64
#if _WIN64
  uint8_t bHook[] = 
  {
    0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV R11, HOOK
    0x41, 0xFF, 0xE3                                            // JMP R11
  };
  *(void**)(&bHook[2]) = &LdrLoadDll_;
#else
  uint8_t bHook[] =
  {
    0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, HOOK
    0xFF, 0xE0                    // JMP EAX
  };
  *(void**)(&bHook[1]) = &LdrLoadDll_;
#endif
#endif

  unsigned long oldProtect = 0;
  LdrLoadDllByteLen = sizeof(bHook);
  if (TRUE == VirtualProtect(_LdrLoadDll, 
                             LdrLoadDllByteLen, 
                             PAGE_EXECUTE_READWRITE,
                             &oldProtect))
  {
    if (nullptr == LdrLoadDllOrigBytes)
    {
      LdrLoadDllOrigBytes = new uint8_t[LdrLoadDllByteLen];
      memcpy(LdrLoadDllOrigBytes, _LdrLoadDll, LdrLoadDllByteLen);
    }
    
    memcpy(_LdrLoadDll, bHook, LdrLoadDllByteLen);
    VirtualProtect(_LdrLoadDll, LdrLoadDllByteLen, oldProtect, &oldProtect);
  }
}

// --------------------------------------------------------------------------------------
// Function: LdrLoadDll_UninstallHook
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::LdrLoadDll_UninstallHook()
{
  unsigned long oldProtect = 0;
  if (TRUE == VirtualProtect(_LdrLoadDll, 
                             LdrLoadDllByteLen, 
                             PAGE_EXECUTE_READWRITE,
                             &oldProtect))
  {
    memcpy(_LdrLoadDll, LdrLoadDllOrigBytes, LdrLoadDllByteLen);
    VirtualProtect(_LdrLoadDll, LdrLoadDllByteLen, oldProtect, &oldProtect);
  }
}

// --------------------------------------------------------------------------------------
// Function: GetSectionMemRegion
// Notes: None.
// --------------------------------------------------------------------------------------
void ModuleMgmt::GetSectionMemRegion(const char* section,
                                     void* imageBase,
                                     void*& address,
                                     uint32_t& nBytes)
{
  // Copy dos header contents to temporary buffer
  unsigned char temp_buf[1024] = { 0 };
  memcpy(temp_buf, imageBase, sizeof(IMAGE_DOS_HEADER));
 
  // Read the FILE header
  uintptr_t bufferSize = sizeof(IMAGE_DOS_HEADER) +
                         reinterpret_cast<IMAGE_DOS_HEADER*>(temp_buf)->e_lfanew;

  uintptr_t addr = reinterpret_cast<uintptr_t>(imageBase) +
                   reinterpret_cast<IMAGE_DOS_HEADER*>(temp_buf)->e_lfanew;

  // Read NT headers
  memcpy(temp_buf, reinterpret_cast<void*>(addr), sizeof(IMAGE_NT_HEADERS));

  // Calculate the entire buffer size needed to retrieve our PE Headers,
  // then read the contents into the buffer.
  IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(temp_buf);
  bufferSize += sizeof(ntHeaders->Signature) +
                sizeof(IMAGE_FILE_HEADER) +
                ntHeaders->FileHeader.SizeOfOptionalHeader +
                (ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

  uint8_t* buffer = new uint8_t[bufferSize];
  memcpy(buffer, imageBase, bufferSize);

  // Retrieve all PE File sections needed to retrieve .text, .*data, etc
  IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
  IMAGE_NT_HEADERS* ntHdrs = reinterpret_cast<IMAGE_NT_HEADERS*>
                             (reinterpret_cast<uintptr_t>(buffer) + dosHdr->e_lfanew);
  if (nullptr == ntHdrs)
  {
    delete[] buffer;
    return;
  }

  // Validate magic and signature before proceeding.
  if ((IMAGE_DOS_SIGNATURE != dosHdr->e_magic) &&
      (IMAGE_NT_SIGNATURE != ntHdrs->Signature))
  {
    delete[] buffer;
    return;
  }

  // Search for the specified section
  IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(ntHdrs);
  for (unsigned int i = 0; i < ntHdrs->FileHeader.NumberOfSections; ++i)
  {
    if (strlen(reinterpret_cast<char*>(pSection[i].Name)) == strlen(section))
    {
      if (0 == memcmp(pSection[i].Name, section, strlen(section)))
      {
        address = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(imageBase) +
                                          pSection[i].VirtualAddress);
        nBytes = pSection[i].Misc.VirtualSize;
        break;
      }
    }
  }

  delete[] buffer;
}

// --------------------------------------------------------------------------------------
// Function: LdrLoadDllHook
// Notes: None.
// --------------------------------------------------------------------------------------
NTSTATUS __stdcall ModuleMgmt::LdrLoadDll_(PWCHAR            PathToFile OPTIONAL,
                                           ULONG             Flags,
                                           PUNICODE_STRING   ModuleFileName,
                                           PHANDLE           ModuleHandle)
{
  char library[MAX_PATH] = { 0 };
  for (size_t i = 0; i < ModuleFileName->Length; ++i)
  {
    library[i] = ModuleFileName->Buffer[i];
  }

#if _DEBUG
  printf("%s: Library=%s\n",
         __FUNCSIG__,
         library);
#endif

  bool skipLibrary = false;
  switch (FilterBehavior)
  {
    case NIVTypes::LIB_BLACKLIST:
    {
      for (size_t i = 0; i < LibraryList.size(); ++i)
      {
        if (std::string::npos != std::string(library).find(LibraryList[i].c_str()))
        {
          skipLibrary = true;
          NIV_Notify(NIVTypes::TAMPER_DETECTED,
                     NIVTypes::LIB_INJECTION,
                     FilterBehavior); // This library is blacklisted
          break;
        }
      }
    }
    break;
    case NIVTypes::LIB_WHITELIST:
    {
      skipLibrary = true;
      for (size_t i = 0; i < LibraryList.size(); ++i)
      {
        if (std::string::npos != std::string(library).find(LibraryList[i].c_str()))
        {
          skipLibrary = false;
          break;
        }
      }

      if (true == skipLibrary)
      {
        NIV_Notify(NIVTypes::TAMPER_DETECTED,
                   NIVTypes::LIB_INJECTION,
                   FilterBehavior); // This library isn't whitelisted
      }
    }
    break;
  }

  if (false == skipLibrary)
  {
    // Temporarily unhook this function
    LdrLoadDll_UninstallHook();

    // Invoke the API
    NTSTATUS status = _LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);

    // Reinstall hook
    LdrLoadDll_InstallHook();

    return status;
  }

  return 0;
}