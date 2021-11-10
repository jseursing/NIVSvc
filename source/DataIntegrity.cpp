#include "crc32.h"
#include "DataIntegrity.h"
#include "NIVService.h"
#include <cstring>
#include <Windows.h>

#if _DEBUG
#include <stdio.h>
#endif
std::vector<uint8_t> test;
// --------------------------------------------------------------------------------------
// Function: Instance
// Notes: None.
// --------------------------------------------------------------------------------------
DataIntegrity* DataIntegrity::Instance()
{
  static DataIntegrity instance;
  return &instance;
}

// --------------------------------------------------------------------------------------
// Function: CRC32Init
// Notes: None.
// --------------------------------------------------------------------------------------
bool DataIntegrity::CRC32Init(void* address, uint32_t nBytes, NIVTypes::CRCEnum id)
{
  // Verify input params range
  // 4-byte alignment required.
  if ((nullptr == address) ||
      (0 == nBytes) ||
      (NIVTypes::CRC_MAX_ID <= id))
  {
    return false;
  }

  // Verify id wasn't already initialized
  if (nullptr != IntegrityHeader[id].baseAddress)
  {
    return false;
  }

  // Fill in integrity header.
  IntegrityHeader[id].baseAddress = address;
  IntegrityHeader[id].nBytes = nBytes - (nBytes % sizeof(uint32_t));

  // Adjust memory page attributes
  unsigned long oldProtect = 0;
  if (TRUE == VirtualProtect(address, 
                             IntegrityHeader[id].nBytes, 
                             PAGE_EXECUTE_READWRITE, 
                             &oldProtect))
  {
    IntegrityHeader[id].crc32 = crc32(address, IntegrityHeader[id].nBytes, 0);
    VirtualProtect(address, nBytes, oldProtect, &oldProtect);
  }

#if _DEBUG
  printf("%s: id=%d address=%p size=%08x crc32=%08X\n",
          __PRETTY_FUNCTION__,
          id,
          IntegrityHeader[id].baseAddress,
          IntegrityHeader[id].nBytes,
          IntegrityHeader[id].crc32);
#endif

  return true;
}

// --------------------------------------------------------------------------------------
// Function: CRC32Register
// Notes: None.
// --------------------------------------------------------------------------------------
bool DataIntegrity::CRC32Register(void* address,
                                  uint32_t nBytes,
                                  NIVTypes::CRCEnum id,
                                  uint32_t _crc32)
{
  // Verify input params range
  // 4-byte alignment required.
  if ((nullptr == address) ||
      (0 == nBytes) ||
      (NIVTypes::CRC_MAX_ID <= id))
  {
    return false;
  }

  // Verify id wasn't already initialized
  if (nullptr != IntegrityHeader[id].baseAddress)
  {
    return false;
  }

  // Fill in integrity header.
  IntegrityHeader[id].baseAddress = address;
  IntegrityHeader[id].nBytes = nBytes - (nBytes % sizeof(uint32_t));

  // If a crc32 value was specified, set it now, otherwise calculate it.
  if (0 == _crc32)
  {
    // Adjust memory page attributes
    unsigned long oldProtect = 0;
    if (TRUE == VirtualProtect(address, 
                               IntegrityHeader[id].nBytes, 
                               PAGE_EXECUTE_READWRITE, 
                               &oldProtect))
    {
      _crc32 = crc32(address, IntegrityHeader[id].nBytes, 0);
      VirtualProtect(address, nBytes, oldProtect, &oldProtect);
    }
  }

  IntegrityHeader[id].crc32 = _crc32;

  return true;
}

// --------------------------------------------------------------------------------------
// Function: CRC32Validate
// Notes: None.
// --------------------------------------------------------------------------------------
void DataIntegrity::CRC32Validate(NIVTypes::CRCEnum id)
{
  if ((nullptr == IntegrityHeader[id].baseAddress) ||
      (0 == IntegrityHeader[id].nBytes) ||
      (NIVTypes::CRC_MAX_ID <= id))
  {
    NIV_Notify(NIVTypes::WARNING,
               NIVTypes::DATA_INTEGRITY, // INVALID PARAM
               id,
               reinterpret_cast<uint32_t>(IntegrityHeader[id].baseAddress),
               IntegrityHeader[id].nBytes); 
    return;
  }

  unsigned long oldProtect = 0;
  if (TRUE == VirtualProtect(IntegrityHeader[id].baseAddress, 
                             IntegrityHeader[id].nBytes, 
                             PAGE_EXECUTE_READWRITE, 
                             &oldProtect))
  {
    uint32_t crc = crc32(IntegrityHeader[id].baseAddress,
                         IntegrityHeader[id].nBytes,
                         0);
    if (IntegrityHeader[id].crc32 != crc)
    {
      NIV_Notify(NIVTypes::TAMPER_DETECTED, 
                 NIVTypes::DATA_INTEGRITY,
                 id,
                 reinterpret_cast<uint32_t>(IntegrityHeader[id].baseAddress),
                 IntegrityHeader[id].crc32,
                 crc);
    }

    VirtualProtect(IntegrityHeader[id].baseAddress,
                   IntegrityHeader[id].nBytes,
                   oldProtect,
                   &oldProtect);
  }
}

// --------------------------------------------------------------------------------------
// Function: DataIntegrity
// Notes: None.
// --------------------------------------------------------------------------------------
DataIntegrity::DataIntegrity() :
  IntegrityHeader(nullptr)
{
  IntegrityHeader = new DataIntHeader[NIVTypes::CRC_MAX_ID];
  memset(IntegrityHeader, 0, NIVTypes::CRC_MAX_ID * sizeof(DataIntHeader));
}

// --------------------------------------------------------------------------------------
// Function: ~DataIntegrity
// Notes: None.
// --------------------------------------------------------------------------------------
DataIntegrity::~DataIntegrity()
{
  delete[] IntegrityHeader;
}