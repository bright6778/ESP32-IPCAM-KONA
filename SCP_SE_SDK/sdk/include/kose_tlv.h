// origin : se05x_tlv.h

#ifndef KOSE_TLV_H_INC
#define KOSE_TLV_H_INC

#define kKOSE_CLA 0x80

typedef enum
{
    SM_NOT_OK = 0xFFFF,                         // Error
    SM_OK = 0x9000,                             // No Error
    SM_ERR_WRONG_LENGTH = 0x6700,               // Wrong length (e.g. C-APDU does not fit into APDU buffer)
    SM_ERR_CONDITIONS_NOT_SATISFIED = 0x6985,   // Conditions not satisfied
    SM_ERR_COMMAND_NOT_ALLOWED = 0x6986,        // Command not allowed - access denied based on object policy
    SM_ERR_SECURITY_STATUS = 0x6982,            // Security status not satisfied
    SM_ERR_WRONG_DATA = 0x6A80,                 // Wrong data provided
    SM_ERR_DATA_INVALID = 0x6984,               // Data invalid - policy set invalid for the given object
    SM_ERR_FILE_FULL = 0x6A84,                  // Not enough memory space available (either transient or persistent memory)
    SM_ERR_APDU_THROUGHPUT = 0x66A6,            // APDU Throughput error
} smStatus_t;

/** struct KoseSession represnting a session in KOSE
*
*/
typedef struct KoseSession
{
    /** Array of 8 bytes represnting session value.*/
    uint8_t value[8];
    /** Indicating session is active*/
    uint8_t hasSession : 1;
    /** Type of authentication for the session*/
    //SE_AuthType_t authType;
    /** auth ID associated with session*/
    //uint32_t auth_id;
    /** Meta Funciton
     *
     * Internall first calls fp_Transform
     * Then calls fp_RawTXn
     * Then calls fp_DeCrypt
     */
    //smStatus_t(*fp_TXn)(struct KoseSession * pSession,
    //    const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen, uint8_t hasle);

    /** API called by fp_TXn. Helps handle UserID/Applet/ECKey to transform buffer.
     *
     * But this API never sends any data out over any communication link. */
    smStatus_t(*fp_Transform)(struct KoseSession * pSession,
        /** IN */
        //const tlvHeader_t *inHdr,
        /** IN */
        uint8_t *inCmdBuf,
        /** IN */
        //size_t inCmdBufLen,
        /** OUT:
         *  For Session less,
         *      For Platform SCP this will be copy of,  inHDR, with outHdr[0] = outHdr[0] | 0x04
         *      For Plain Session: Same as inHDR
         *
         *  For With Session:
         *      This will be with TLV Header for Wrapped Session Command
         */
        //tlvHeader_t *outHdr,
        /** OUT: For Session less, this will be copy of inCmdBuf
         *
         * For session based impelementation, this will have
         * TAG=Session, L=8,V=Session,TAG=TAG1,L=inCmdBufLen,inCmdBuf */
        uint8_t * pTxBuf,
        /** IN,OUT: */
        //size_t * pTxBufLen,
        /** IN */
        uint8_t hasle);

    /** API called by fp_TXn. Helps handle Applet/Fast SCP to decrypt buffer.
    *
    * But this API never reads any data */
    smStatus_t(*fp_DeCrypt)(struct KoseSession * pSession,
        //size_t prevCmdBufLen,
        uint8_t *pInRxBuf,
        //size_t *pInRxBufLen,
        uint8_t hasle);
#if SSS_HAVE_APPLET_SE05X_IOT
    /** It's either a minimal/single implemntation that calls smCom_TransceiveRaw()
     *
     * if pTunnelCtx is Null, directly call smCom_TransceiveRaw()
     *
     * Or an API part of tunnel ctx that can do PlatformSCP */
    smStatus_t (*fp_RawTXn)(void *conn_ctx,
        struct _sss_se05x_tunnel_context *pChannelCtx,
        SE_AuthType_t currAuth,
        const tlvHeader_t *hdr,
        uint8_t *cmdBuf,
        size_t cmdBufLen,
        uint8_t *rsp,
        size_t *rspLen,
        uint8_t hasle);
    /** pChannelCtx holds the context information for SE05x tunnel communication.
    *
    */
    struct _sss_se05x_tunnel_context * pChannelCtx;
#endif
#if SSS_HAVE_APPLET
    smStatus_t(*fp_Transmit)(
        SE_AuthType_t currAuth,
        const tlvHeader_t *hdr,
        uint8_t *cmdBuf,
        size_t cmdBufLen,
        uint8_t *rsp,
        size_t *rspLen,
        uint8_t hasle);
#endif
    /** pdynScp03Ctx holds the dynamic context information for SCP03 channel */
    //NXSCP03_DynCtx_t *pdynScp03Ctx;

    /**Connection data context */
    void *conn_ctx;
    /** applet version*/
    uint32_t applet_version;

/*
#if SSS_HAVE_SCP_SCP03_SSS
#if (defined(USE_RTOS) && (USE_RTOS == 1))
    SemaphoreHandle_t scp03_lock;
    uint8_t scp03_lock_init;
#elif (__GNUC__ && !AX_EMBEDDED)
    pthread_mutex_t scp03_lock;
    uint8_t scp03_lock_init;
#endif
#endif // SSS_HAVE_SCP_SCP03_SSS
*/
} KoseSession_t;

typedef KoseSession_t *pKoseSession_t;

#endif