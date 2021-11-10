#pragma once
#include "NIVTypes.h"

class DataIntegrity
{
public:
  
  static DataIntegrity* Instance();
  bool CRC32Init(void* address, 
                 uint32_t nBytes, 
                 NIVTypes::CRCEnum id);
  bool CRC32Register(void* address, 
                     uint32_t nBytes, 
                     NIVTypes::CRCEnum id,
                     uint32_t _crc32 = 0);
  void CRC32Validate(NIVTypes::CRCEnum id);

private:

  DataIntegrity();
  ~DataIntegrity();

  struct DataIntHeader
  {
    void*                baseAddress;
    uint32_t             nBytes;
    uint32_t             crc32;
  };
  DataIntHeader* IntegrityHeader;
};