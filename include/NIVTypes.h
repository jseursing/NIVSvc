#pragma once
#include <stdint.h>

#ifdef _MSC_VER 
#define __PRETTY_FUNCTION__ __FUNCSIG__ 
#endif


class NIVTypes
{
public:
  
  // --------------------------------------------
  // The following types define a notification by
  // NIVService when a warning or potential 
  // tampering is detected
  // --------------------------------------------
  enum NotifyLevel
  {
    WARNING,
    TAMPER_DETECTED
  };

  enum NotifyType
  {
    DATA_INTEGRITY,
    LIB_INJECTION,
    DBG_DETECTION,
    COMMUNICATION
  };

  enum BehaviorType
  {
    LIB_BLACKLIST,
    LIB_WHITELIST
  };

  struct NIVNotification
  {
    NotifyLevel level;
    NotifyType  notifyType;
    uintptr_t   parameters[4];
  };

  static const char* NotifyString(NotifyLevel v)
  {
    const char* strs[] =
    {
      "WARNING\0",
      "TAMPER\0"
    };
    return strs[v];
  }

  static const char* TypeString(NotifyType v)
  {
    const char* strs[] =
    {
      "DATA_INTEGRITY\0",
      "LIB_INJECTION\0",
      "DBG_DETECTION\0",
      "COMMUNICATION\0"
    };
    return strs[v];
  }

  // --------------------------------------------
  // The following types are used for data
  // integrity.
  // --------------------------------------------
  enum CRCEnum
  {
    CRC_ID_0,
    CRC_ID_1,
    CRC_ID_2,
    CRC_ID_3,
    CRC_ID_4,
    CRC_ID_5,
    CRC_ID_6,
    CRC_ID_7,
    CRC_ID_8,
    CRC_ID_9,
    CRC_MAIN_ID,
    NIV_MAIN_ID,
    CRC_MAX_ID
  };

  // --------------------------------------------
  // The following types are used for session
  // management (communication).
  // --------------------------------------------
  struct SessionMessage
  {
    uint32_t timeMs;
    uint32_t queryResponse;
    uint32_t signature;
    uint32_t checksum;
  };

  // The maximum time a session can be processed is 1 minute
  static const uint32_t MAX_SESSION_FREQ = 60 * 1000;
};