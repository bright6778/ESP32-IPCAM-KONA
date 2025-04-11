#ifndef _SM_API_
#define _SM_API_

//#include "sm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Contains the information required to resume a connection with the Security Module.
 * Its content is only to be interpreted by the Host Library.
 * The semantics of the param1 and param2 fields depends on the link layer.
 */
typedef struct {
    U16 connType;
    U16 param1;          //!< Useage depends on link layer
    U16 param2;          //!< Useage depends on link layer
    U16 hostLibVersion;  //!< MSByte contains major version (::AX_HOST_LIB_MAJOR); LSByte contains minor version of HostLib (::AX_HOST_LIB_MINOR)
    U32 appletVersion;   /*!< MSByte contains major version;
                              3 leading bits of LSByte contains minor version of Applet;
                              Last bit of LSByte encodes whether Applet is in Debug Mode, a '1' means 'Debug Mode' is available */
    U16 sbVersion;       //!< Expected to be 0x0000
    U8  select;          //!< Applet selection mode
    U8  sessionResume;   //!< Set to 1 to resume an open session with SE
} SmCommState_t;

#ifdef __cplusplus
}
#endif
#endif //_SM_API_
