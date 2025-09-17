#ifndef _SM_API_
#define _SM_API_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum
{
    kType_SE_Conn_Type_NONE = 0,
    kType_SE_Conn_Type_UART = 1,
    kType_SE_Conn_Type_I2C = 2
} KSS_Conn_Type_t;

/**
 * Contains the information required to resume a connection with the Security Module.
 * Its content is only to be interpreted by the Host Library.
 * The semantics of the param1 and param2 fields depends on the link layer.
 */
typedef struct {
    uint16_t connType;
    uint16_t param1;          //!< Useage depends on link layer
    uint16_t param2;          //!< Useage depends on link layer
    uint16_t hostLibVersion;  //!< MSByte contains major version (::AX_HOST_LIB_MAJOR); LSByte contains minor version of HostLib (::AX_HOST_LIB_MINOR)
    uint32_t appletVersion;   /*!< MSByte contains major version;
                              3 leading bits of LSByte contains minor version of Applet;
                              Last bit of LSByte encodes whether Applet is in Debug Mode, a '1' means 'Debug Mode' is available */
    uint16_t sbVersion;       //!< Expected to be 0x0000
    uint8_t  sessionResume;   //!< Set to 1 to resume an open session with SE
} SmCommState_t;

#ifdef __cplusplus
}
#endif
#endif //_SM_API_
