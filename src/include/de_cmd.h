/**
 * @file de_cmd.h
 * @author thuan@duali.com
 * @date 02/02/2023.
 * @brief This is command and response IDs that is supported by Duali Electronic.
 */

#ifndef DE_COMMAND_CODE_H
#define DE_COMMAND_CODE_H


/**
 *  @brief Duali command
 */

/* Common Command*/
#define _DE_GET_PRODUCT_VERSION         0x05
#define _DE_VERSION				        0x16
#define _DE_INF_GET                     0x09


/* Device Control */
#define _DE_RFON				        0x10
#define _DE_RFOFF				        0x11
#define _DE_RESET				        0x12
#define _DE_BUZZER				        0x13
#define _DE_DEV_CHANGE				    0x15
#define _DE_TRXSPEED				    0x1A
#define _DE_RF_WTX				        0x1B
#define _DE_CONTACT_WTX				    0x1C
#define _DE_FLASH				        0x1F
#define _DE_CONTACT_ANTI_TEARING		0x18
#define _DE_RF_ANTI_TEARING			    0x19
#define _DE_RF_RESET				    0x20
#define _DE_GET_UID                     0x4D
#define _DE_SET_UID                     0x4E
#define _DE_RW_WRITE                    0x7A
#define _DE_RW_READ                     0x7B
#define _DE_LCD_CONTROL                 0x7C
#define _DE_RTC_CONTROL                 0x7D

/* TYPE C */
#define _DEC_TRANSPARENT			    0x50
#define _DEC_POLLING_NOENC			    0x51
#define _DEC_READ_NOENC				    0x52
#define _DEC_WRITE_NOENC			    0x53

/* TYPE B */
#define _DEB_TRANSPARENT			    0x60
#define _DEB_TRANSPARENT2			    0x6E
#define _DEB_BFRAMING				    0x6F

/* TYPE A */
#define _DEA_IDLE_REQ				    0x21
#define _DEA_WAKEUP_REQ				    0x22
#define _DEA_ANTICOLL				    0x23
#define _DEA_SELECT				        0x24
#define _DEA_AUTH				        0x25
#define _DEA_HALT				        0x26
#define _DEA_READ				        0x27
#define _DEA_WRITE				        0x28
#define _DEA_INCREMENT				    0x29
#define _DEA_DECREMENT				    0x2A
#define _DEA_INC_TRANS				    0x2B
#define _DEA_DEC_TRANS				    0x2C
#define _DEA_RESTORE				    0x2D
#define _DEA_TRANSFER				    0x2E
#define _DEA_LOADKEY				    0x2F
#define _DEA_AUTHKEY				    0x30
#define _DEA_REQ_ANTI_AUTH			    0x31
#define _DEA_REQ_ANTI_AUTHKEY			0x32
#define _DEA_INC_TRANS2				    0x33
#define _DEA_DEC_TRANS2				    0x34
#define _DEA_REQ_ANTI_AUTH_RD			0x35
#define _DEA_REQ_ANTI_AUTHKEY_RD    	0x36
#define _DEA_REQ_ANTI_AUTH_WR			0x37
#define _DEA_REQ_ANTI_AUTHKEY_WR		0x38
#define _DEA_REQ_ANTI_SEL			    0x39
#define _DEA_UWRITE  				    0x3B
#define _DEA_ANTI_SEL_LEVEL			    0x3D
#define _DEA_ANTICOLL_LEVEL			    0x3E
#define _DEA_SELECT_LEVEL			    0x3F
#define _DEA_DEVINFO				    0x40
#define _DEA_TRANSPARENT			    0x41
#define _DEA_TRANSPARENT2			    0x47
#define _DEA_BITMODE				    0xA1
#define _DEA_BITMODEANTI			    0xA2
#define _DEA_BITMODE2				    0xA4

/* TYPE A/B */
#define _DE_FIND_CARD				    0x4C
#define _DE_APDU				        0x61
#define _DEAB_RW_WRITE				    0x7A
#define _DEAB_RW_READ				    0x7B


/* ISO15693 */
#define _DED_Inventory				    0x70
#define _DED_Select				        0x71
#define _DED_Read				        0x72
#define _DED_Write				        0x73
#define _DED_Transparent			    0x74
#define _DED_Eof				        0x78

/* PCSC */
#define _PCSC_CONNECT                   0x80
#define _PCSC_POLLING_SET               0x81
#define _PCSC_POLLING_SET2              0x82

/* QR Module define */
#define QR_PWR_ON	                    'P'
#define QR_PWR_OFF	                    'O'
#define QR_SCAN_ON	                    'N'
#define QR_SCAN_OFF	                    'M'
#define QR_SCAN_RESET	                'L'
#define QR_TRIG_MODE	                '6'
#define QR_PRESENTATION_MODE_NORMAL	    '7'
#define QR_PRESENTATION_MODE_CONTINUE_SCAN	'8'
#define QR_CRLF			                'F'
#define QR_FACTORY_RESET	            '0'
//#define QR_ILLUMINATION_OFF	            0x05
#define QR_ILLUMINATION_ON	            0x06
#define QR_ALLSYMBOL_READ	            0x07


/**
 * @brief Duali responses
 */
#define _DE_RES_NONE                    0x00
#define _DE_RES_NO_RESPONSE             0x02
#define _DE_RES_CHECKSUM_WRONG          0x03
#define _DE_RES_SC_NOT_INSERTED         0x04
#define _DE_RES_MF_AUTH_ERR             0x05
#define _DE_RES_SC_TURN_OFF             0x05
#define _DE_RES_WRONG_PARITY_A          0x06
#define _DE_RES_UNKNOWN_CMD             0x07
#define _DE_RES_CHECK_BYTE_UID_ERR      0x08
#define _DE_RES_CMD_NOT_AUTH            0x0A
#define _DE_RES_BIT_COUNT_RX_ERR        0x0B
#define _DE_RES_DATA_LENGTH_INVALID     0x0C
#define _DE_RES_MF_WRITE_DATA_ERR                       0x0F
#define _DE_RES_MF_INCREASE_DATA_ERR                    0x10
#define _DE_RES_MF_DECREASE_DATA_ERR                    0x11
#define _DE_RES_FELICA_READ_ERR                         0x12
#define _DE_RES_OVERLOAD_DATA_FROM_CARD                 0x13
#define _DE_RES_DATA_OUT_OF_FRAME                       0x15
#define _DE_RES_UNSUPPORT_CMD                           0x17
#define _DE_RES_COLLISION_FROM_CARD                     0x18
#define _DE_RES_RF_CHIP_ERR                             0x19
#define _DE_RES_CHAINING_RETRY_OVERFLOWED_COUNT         0x21
#define _DE_RES_ACK_RECEIVED_FOR_DESELECTED             0x22
#define _DE_RES_MAXIMUM_RETRY_LIMIT                     0x23
#define _DE_RES_RECEIVED_BUFFER_TO_SMALL                0x31
#define _DE_RES_RECEIVED_BUFFER_OVERLOAD                0x32
#define _DE_RES_NFC_RF_ERR                              0x33
#define _DE_RES_PROTOCOL_ERR                            0x34
#define _DE_RES_NFC_DATA_INVALID                        0x37
#define _DE_RES_NFC_WRONG_PARAM                         0x3C
#define _DE_RES_NFC_PARAM_INVALID                       0x3D
#define _DE_RES_NFC_CMD_UNSUPPORTED                     0x3F

#define _DE_RES_RF_INTERFACE_NOT_ENABLE                 0x40
#define _DE_RES_ACK_SUPPOSED                            0x41
#define _DE_RES_NACK_RECEIVED                           0x42

#define _DE_RES_FIFO_ERR                                0x6D



#endif //DE_COMMAND_CODE_H
