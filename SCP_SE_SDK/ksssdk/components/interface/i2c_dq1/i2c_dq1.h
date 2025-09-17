#ifndef _LINUX_I2C_H_
#define _LINUX_I2C_H_

#define DEBUG_MSG
// #define IRQ_TIME_MEASURE

#define I2C_DEV_PATH					"/dev/i2c-2"
#define I2C_ADDRESS						(0x60)

#define BUFFER_MAX						(256)

#include "kose_tlv.h"
/**
 * @brief open i2c device
 *     This function opens the i2c device defined in I2C_DEV_PATH and returns the file descriptor.
 * @return The file descriptor of an opened i2c device 
 */
int se_i2c_open(void);

/**
 * @brief close i2c device
 *     This function takes and opened file descriptor and closes it.
 * @param fd The file descriptor to be closed
 */
void se_i2c_close(int fd);

/**
 * @brief write data to an i2c device
 *     This function takes PCB and data buffer and write the data to an file descriptor.
 *     The address of i2c device is predefined in I2C_ADDRESS.
 * @param cPCB Protocol Control Byte
 * @param pDataBuffer pointer to the data to be sent
 * @param nDataLength The length of the data to write
 * @param fd The file descriptor of i2c device
 */
int se_i2c_write(unsigned char cPCB, unsigned char *pDataBuffer, int nDataLength,  int fd);

/**
 * @brief read data from an i2c device
 *     This function read the data from file descriptor and writes it to buffer pointer. 
 *     The address of i2c device is predefined in I2C_ADDRESS.
 * @param cPCB Protocol Control Byte
 * @param pDataBuffer pointer to the buffer for storing data
 * @param nDataLength length of the data to read
 * @param fd The file descriptor of i2c device
 */
int se_i2c_read(unsigned char cPCB, unsigned char *pDataBuffer, int *nDataLength, int fd);

int i2c_power_down(int i2c_fd);
int i2c_wake_up(int i2c_fd);
int i2c_soft_reset(int i2c_fd);
int i2c_read_ATR(int i2c_fd, unsigned char *pBuffer, int *nDataLength);
int i2c_exchange_PPS(int i2c_fd, unsigned char *pBuffer, int *nDataLength);
int i2c_get_status(int i2c_fd, unsigned char *pBuffer, int *nDataLength);
int i2c_clear_status(int i2c_fd, unsigned char *pBuffer, int *nDataLength);
int i2c_exchange_data_MS(int i2c_fd, unsigned char *pBuffer, int nDataLength);
int i2c_exchange_data_SM(int i2c_fd, unsigned char *pBuffer, int *nDataLength);

// KSS SDK
kss_status_t i2c_se_connect(SE_Connect_Ctx_t *se_conn_ctx, unsigned char *pATR, uint8_t *nATRLength);
smStatus_t i2c_transaction_apdu(struct KoseSession * pSession, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen);

#endif // _LINUX_I2C_H_

