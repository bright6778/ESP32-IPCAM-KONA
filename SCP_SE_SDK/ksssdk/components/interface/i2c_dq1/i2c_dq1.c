#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include "i2c_dq1.h"

#include <stdint.h>
#include <errno.h>

#define PCB_POWERDOWN 	0x0F
#define PCB_WAKEUP 		0x1F
#define PCB_GETSTATUS 	0x01

int scms = 0; // Sequence Counter Master to Slave
bool retry_flag = false;

#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>


#include "kona_kss_debug.h"
#include "kona_kss_kose_types.h"
//#include "scp03_Types.h"

static const char *TAG = "i2c_dq1.c";

static unsigned char       pBuffer[BUFFER_MAX] = {0,};
static uint8_t nDataLength = 0;

int i2c_read_reg(unsigned char *pWriteBuf, unsigned short sWriteLength, unsigned char *pReadBuf, unsigned short sReadLength, int fdI2c)
{
	int ret = 0;
	struct i2c_msg                msg[2];
	struct i2c_rdwr_ioctl_data data;

	//write msg
	msg[0].addr = (__u16)I2C_ADDRESS;
	msg[0].flags = (__u16)0;			// write : low
	msg[0].len = (__u16)sWriteLength;
	msg[0].buf = (__u8 *)pWriteBuf;

	//read msg
	msg[1].addr = (__u16)I2C_ADDRESS;
	msg[1].flags = I2C_M_RD; /* 0x01 */
	msg[1].len = (__u16)sReadLength;
	msg[1].buf = (__u8 *)pReadBuf;

	data.msgs = &msg[0];
	data.nmsgs = 2;

	ret = ioctl(fdI2c, I2C_RDWR, &data);
	if(ret <= 0) printf("i2c_read_reg error \n");
	return ret;
}

int i2c_read_reg_waited(unsigned char *pWriteBuf, unsigned short sWriteLength, unsigned char *pReadBuf, unsigned short *sReadLength, int fdI2c)
{
	int ret = 0;
	struct i2c_msg                msg[2];
	struct i2c_rdwr_ioctl_data data;
	int cPCB_local = pWriteBuf[0];
	unsigned short sLocalReadLength = 0;

	unsigned char getStatus_res[BUFFER_MAX] = {0,};
	int getStatusLen = 0;

	if (*sReadLength > 0) {
		struct i2c_msg msg[2];
        struct i2c_rdwr_ioctl_data data;

        // write
        msg[0].addr  = (__u16)I2C_ADDRESS;  // 7-bit 그대로
        msg[0].flags = 0;
        msg[0].len   = (__u16)sWriteLength;
        msg[0].buf   = (__u8 *)pWriteBuf;

        // read (고정 길이)
        msg[1].addr  = (__u16)I2C_ADDRESS;
        msg[1].flags = I2C_M_RD;
        msg[1].len   = (__u16)*sReadLength;
        msg[1].buf   = (__u8 *)pReadBuf;

        data.msgs  = &msg[0];
        data.nmsgs = 2;

		ret = ioctl(fdI2c, I2C_RDWR, &data);
		if (ret != 2) { perror("I2C_RDWR fixed read"); return -1; }
		//kss_debug_showframe("sReadLength > 0, pReadBuf", pReadBuf, *sReadLength);

        return ret;
    }
	else
	{
		struct i2c_msg msg[2];
        struct i2c_rdwr_ioctl_data data;

        // write
        msg[0].addr  = (__u16)I2C_ADDRESS;  // 7-bit 그대로
        msg[0].flags = 0;
        msg[0].len   = (__u16)sWriteLength;
        msg[0].buf   = (__u8 *)pWriteBuf;

        // read (고정 길이)
        msg[1].addr  = (__u16)I2C_ADDRESS;
        msg[1].flags = I2C_M_RD;
        msg[1].len   = 1;
        msg[1].buf   = (__u8 *)pReadBuf;

        data.msgs  = &msg[0];
        data.nmsgs = 2;

        ret = ioctl(fdI2c, I2C_RDWR, &data);
        if (ret != 2) { perror("I2C_RDWR fixed read"); return -1; }
		*sReadLength = pReadBuf[0];
		*sReadLength += 1;
		
		//LOGD(TAG, "sReadLength1 : %d", *sReadLength );

		// length = 2
		size_t count = 0;
		if(*sReadLength == 2){
			while (cPCB_local != PCB_GETSTATUS)
			{
				ret = i2c_get_status(fdI2c, getStatus_res, &getStatusLen);
				if (ret < 0) { perror("I2C_RDWR fixed read1"); return -1; }

				//LOGD(TAG, "getStatusLen : %d", getStatusLen);
				if(getStatusLen == 3 && getStatus_res[0] == 0x02){
					//kss_debug_showframe("retry exchange SM", pWriteBuf, 1);
					*sReadLength = 1;
					ret = i2c_read_reg_waited(pWriteBuf, 1, pReadBuf, sReadLength, fdI2c);
					//LOGD("retry", "retry length : %d", *sReadLength);
					if (ret != 2) { perror("I2C_RDWR fixed read2"); return -1; }
					break;
				}
				count++;
				delay(10);
				if(count > 100){
					break;
				}
			}
			if (cPCB_local == PCB_GETSTATUS)
			{
				return ret;
			}		
		}

		// length = 3
		else if(*sReadLength == 3){
			return ret;
		}

		// length >= 4
		else if(*sReadLength >= 4){	// 바로 응답온 경우
			
			//LOGD(TAG, "sReadLength2 : %d", *sReadLength );
			//kss_debug_showframe(TAG, pReadBuf, *sReadLength);
			//kss_debug_showframe(TAG, pWriteBuf, 1);
			ret = i2c_read_reg(pWriteBuf, 1, pReadBuf, *sReadLength, fdI2c);
			if (ret != 2) { perror("I2C_RDWR fixed read"); return -1; }
			return ret;
		}

		// retry
		*sReadLength = pReadBuf[0];
		*sReadLength += 1;
		//LOGD(TAG, "sReadLength3 : %d", *sReadLength );
		ret = i2c_read_reg_waited(pWriteBuf, 1, pReadBuf, sReadLength, fdI2c);
		if (ret != 2) { perror("I2C_RDWR fixed read2"); return -1; }
		return ret;
	}
	printf("failed!\n");
    errno = ENOTSUP;
    return -1;
}

int se_i2c_read(unsigned char cPCB, unsigned char* pDataBuffer, int *nDataLength, int fd)
{
	int requestbytes = 0;
	int ret = 0;
	int index = 0;
	unsigned char pWriteBuffer[1] = {0};

	if(*nDataLength > BUFFER_MAX - 1)
		*nDataLength = BUFFER_MAX - 1;

	pWriteBuffer[0] = cPCB;

	#ifdef DEBUG_MSG
	printf("i2c read : PCB = 0x%02X, read length = %d \n", pWriteBuffer[0], *nDataLength);
	#endif	

	//ret = i2c_read_reg(pWriteBuffer, 1, pDataBuffer, nDataLength, fd);
	ret = i2c_read_reg_waited(pWriteBuffer, 1, pDataBuffer, nDataLength, fd);
#ifdef DEBUG_MSG
	printBuffer(pDataBuffer, *nDataLength);
#endif

	return ret;
}

int i2c_write_reg(unsigned char *pInBuf, unsigned short sInBufLength, int fdI2c)
{
	int ret = 0;
	struct i2c_msg                msg[2];
	struct i2c_rdwr_ioctl_data data;

	msg[0].addr = (__u16)I2C_ADDRESS;
	msg[0].flags = (__u16)0;			// write : low
	msg[0].len = (__u16)sInBufLength;
	msg[0].buf = (__u8 *)pInBuf;

	data.msgs = &msg[0];
	data.nmsgs = 1;

	ret = ioctl(fdI2c, I2C_RDWR, &data);

	// test
	/*
	int index = 0;
	for(int i = 0; i < sInBufLength; i++)
    {
        if ((i > 0) && (i % 16 == 0))
        {
            index += 0x10;
            printf("\n");
        }

        if (i % 16 == 0)
        {
            printf("%02X | ", index);
        }

        printf("%02X ", pInBuf[i]);
		//printf("%02X ", data.msgs->buf[i]);
    }
	printf("\n");
	*/
	if(ret <= 0) printf("i2c_write_reg error \n");
	return ret;
}

int se_i2c_write(unsigned char cPCB, unsigned char* pDataBuffer, int nDataLength, int fd)
{
	unsigned char 	pWriteBuffer[BUFFER_MAX] = {0,};
	unsigned int 	nWriteBufferLength = 0;
	int ret = 0;

	if(nDataLength > BUFFER_MAX - 1)
		return ret;

	pWriteBuffer[nWriteBufferLength] = cPCB;
	nWriteBufferLength++;		// PCB count

	#ifdef DEBUG_MSG
	printf("i2c write : PCB = 0x%02X, write length = %d \n", pWriteBuffer[0], nDataLength);
	#endif

	if(nDataLength > 0)
	{
		pWriteBuffer[nWriteBufferLength] = nDataLength;
		nWriteBufferLength++;		// LENGTH count
		for(int i=0; i < nDataLength; i++)
		{
			pWriteBuffer[nWriteBufferLength] = pDataBuffer[i];
			nWriteBufferLength++;
		}
	}

	ret = i2c_write_reg(pWriteBuffer, nWriteBufferLength, fd);
#ifdef DEBUG_MSG
	printBuffer(pWriteBuffer, nWriteBufferLength);
#endif

	return ret;
}

int se_i2c_open(void)
{
	int fd = 0;
	
	fd = open(I2C_DEV_PATH, O_RDWR);
	if(fd > 0)
	{
		#ifdef DEBUG_MSG
		printf("%s opened \n", I2C_DEV_PATH);
		#endif
	}
	else
	{
		printf("%s open failed \n", I2C_DEV_PATH);
	}

	ioctl(fd, I2C_TIMEOUT, 100);
    ioctl(fd, I2C_RETRIES, 2);

	scms = 0;

	return fd;
}

void se_i2c_close(int fd)
{
	if(fd)
	{
		scms = 0;
		close(fd);
		#ifdef DEBUG_MSG
		printf("%s closed \n", I2C_DEV_PATH);
		#endif		
	}
}

int i2c_power_down(int i2c_fd)
{
    // Command : Power Down
#ifdef DEBUG_MSG
    printf("Command : Power Down\n");
#endif
    unsigned char cPCB;
    int nDataLength;
    unsigned char       pBuffer[BUFFER_MAX] = {0,};
    int nRet;

    cPCB = 0x0F;            
    nDataLength = 0;
    nRet = se_i2c_write(cPCB, pBuffer, nDataLength, i2c_fd);
    return nRet;
}

int i2c_wake_up(int i2c_fd)
{
    // Command : Wake Up
#ifdef DEBUG_MSG
    printf("Command : Wake Up\n");
#endif
    unsigned char cPCB;
    int nDataLength;
    unsigned char       pBuffer[BUFFER_MAX] = {0,};
    int nRet;

    cPCB = 0x1F;            
    nDataLength = 0;
    nRet = se_i2c_write(cPCB, pBuffer, nDataLength, i2c_fd);
    return nRet;
}

int i2c_soft_reset(int i2c_fd)
{
    // Command : Soft Reset
#ifdef DEBUG_MSG
    printf("Command : Soft Reset\n");
#endif
    unsigned char cPCB;
    int nRet;
	int nDataLength;
    unsigned char       pBuffer[BUFFER_MAX] = {0,};

    cPCB = 0x03;            
    nDataLength = 2;
    nRet = se_i2c_read(cPCB, pBuffer, &nDataLength, i2c_fd);

	if(nRet > 0)
	{
		if(pBuffer[1] != 0x03) return -1;
	}
    return nRet;
}

int i2c_read_ATR(int i2c_fd, unsigned char *pBuffer, int *nDataLength)
{
    // Command : Read Answer to Reset
#ifdef DEBUG_MSG
    printf("Command : Read Answer to Reset\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = 0x07;            
    *nDataLength = 0;    
    nRet = se_i2c_read(cPCB, pBuffer, nDataLength, i2c_fd);

    return nRet;
}

int i2c_exchange_PPS(int i2c_fd, unsigned char *pBuffer, int *nDataLength)
{
    // Command : Exchange Protocol and Parameter Selection
#ifdef DEBUG_MSG
    printf("Command : Exchange Protocol and Parameter Selection\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = 0xCB;            
    *nDataLength = 0x02;
    nRet = se_i2c_read(cPCB, pBuffer, nDataLength, i2c_fd);

    return nRet;
}

int i2c_get_status(int i2c_fd, unsigned char *pBuffer, int *nDataLength)
{
    // Command : Get Status
#ifdef DEBUG_MSG
    printf("Command : Get Status\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = 0x01;            
    *nDataLength = 0x00;
    //nRet = se_i2c_read(cPCB, pBuffer, nDataLength, i2c_fd);
	
	unsigned long funcs = 0;
    if (ioctl(i2c_fd, I2C_FUNCS, &funcs) < 0) { perror("I2C_FUNCS"); return -1; }

    if (ioctl(i2c_fd, I2C_SLAVE, I2C_ADDRESS) < 0) { perror("I2C_SLAVE"); return -1; }

    union i2c_smbus_data d;
	struct i2c_smbus_ioctl_data args = {
		.read_write = I2C_SMBUS_READ,
		.command    = cPCB,           
		.size       = I2C_SMBUS_BLOCK_DATA,   // [len][data...], len<=32
		.data       = &d
	};
	
	nRet = ioctl(i2c_fd, I2C_SMBUS, &args);
	if (nRet < 0) { perror("i2c_get_status"); return -1; }

	*nDataLength = d.block[0] + 1;
	memcpy(pBuffer, &d.block[0], *nDataLength);

#ifdef DEBUG_MSG
	printBuffer(pBuffer, *nDataLength);
#endif
    return nRet;
}

int i2c_clear_status(int i2c_fd, unsigned char *pBuffer, int *nDataLength)
{
    // Command : clear status
#ifdef DEBUG_MSG
    printf("Command : clear status\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = 0x81;            
    *nDataLength = 0x00;
    
	unsigned long funcs = 0;
    if (ioctl(i2c_fd, I2C_FUNCS, &funcs) < 0) { perror("I2C_FUNCS"); return -1; }

    if (ioctl(i2c_fd, I2C_SLAVE, I2C_ADDRESS) < 0) { perror("I2C_SLAVE"); return -1; }

    union i2c_smbus_data d;
	struct i2c_smbus_ioctl_data args = {
		.read_write = I2C_SMBUS_READ,
		.command    = cPCB,           
		.size       = I2C_SMBUS_BLOCK_DATA,   // [len][data...], len<=32
		.data       = &d
	};
	
	nRet = ioctl(i2c_fd, I2C_SMBUS, &args);
	if (nRet < 0) { perror("i2c_clear_status"); return -1; }

	*nDataLength = d.block[0] + 1;
	memcpy(pBuffer, &d.block[0], *nDataLength);

#ifdef DEBUG_MSG
	printBuffer(pBuffer, *nDataLength);
#endif

	return nRet;
}

int i2c_exchange_data_MS(int i2c_fd, unsigned char *pBuffer, int nDataLength)
{
    // Command : Exchange Data Master to Slave
#ifdef DEBUG_MSG
    printf("Command : Exchange Data Master to Slave\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = ((scms << 4) | 0x00);
    nRet = se_i2c_write(cPCB, pBuffer, nDataLength, i2c_fd);
	return nRet;
}

int i2c_exchange_data_SM(int i2c_fd, unsigned char *pBuffer, int *nDataLength)
{
    // Command : Exchange Data Slave to Master
#ifdef DEBUG_MSG
    printf("Command : Exchange Data Slave to Master\n");
#endif
    unsigned char cPCB;
    int nRet;

    cPCB = ((scms << 4) | 0x02);
    //*nDataLength = 0x00;
    nRet = se_i2c_read(cPCB, pBuffer, nDataLength, i2c_fd);

    return nRet;
}

kss_status_t i2c_se_connect(SE_Connect_Ctx_t *se_conn_ctx, unsigned char *pATR, uint8_t *nATRLength)
{
	kss_status_t retval = kStatus_KSS_Success;
	int16_t nRet = 0;

	se_conn_ctx->connType = kType_SE_Conn_Type_I2C;
    se_conn_ctx->conn_ctx = &i2c_transaction_apdu;
	
	se_conn_ctx->i2cAddress = se_i2c_open();

	nRet = i2c_wake_up(se_conn_ctx->i2cAddress);
	if(nRet < 0){
		LOGE(TAG, "i2c_wake_up failed");
		return kStatus_KSS_Fail;
	}

	delay(100);

	nRet = i2c_soft_reset(se_conn_ctx->i2cAddress);
	if(nRet < 0){
		LOGE(TAG, "i2c_soft_reset failed");
		return kStatus_KSS_Fail;
	}

	delay(100);

	nRet = i2c_read_ATR(se_conn_ctx->i2cAddress, pATR, nATRLength);
	if(nRet < 0){
		LOGE(TAG, "i2c_read_ATR failed");
		return kStatus_KSS_Fail;
	}

	delay(100);

	nRet = i2c_exchange_PPS(se_conn_ctx->i2cAddress, pBuffer, &nDataLength);
	if(nRet < 0){
		LOGE(TAG, "i2c_exchange_PPS failed");
		return kStatus_KSS_Fail;
	}

	delay(100);

    return retval;
}


static int i2c_transaction_set_apdu(int i2c_addr, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen)
{
	int nRet = 0;
	int cPCB_local = cmdBuf[0];
	unsigned char getStatus_res[BUFFER_MAX] = {0,};
	int getStatusLen = 0;
	int exchangeRspLen = 0;
	int i2cRstLen = *rspLen + 2;	// length(1) + pcb(1)

	nRet = i2c_exchange_data_MS(i2c_addr, cmdBuf, cmdBufLen);
    if(nRet < 0) return nRet;

	memset(pBuffer, 0, BUFFER_MAX);
	
    //nRet = i2c_exchange_data_SM(i2c_addr, rsp, &exchangeRspLen);
	//kss_debug_showframe(TAG, rsp, exchangeRspLen);
	//LOGD(TAG, "exchangeRspLen : %d", exchangeRspLen);

	nRet = i2c_exchange_data_SM(i2c_addr, rsp, rspLen);
	if(nRet < 0) return nRet;

	

	/*
	if(exchangeRspLen == 2 && rsp[1] == 0x11 && cPCB_local != PCB_GETSTATUS){
		while(1)
		{
			nRet = i2c_get_status(i2c_addr, getStatus_res, &getStatusLen);
			if (nRet < 0) { perror("i2c_get_status error"); return -1; }
			if(getStatusLen == 3 && getStatus_res[0] == 0x02){
				//pWriteBuf[0] = scms | 0x02;
				*rspLen = i2cRstLen + 2;	// sw(2)
				nRet = i2c_exchange_data_SM(i2c_addr, rsp, rspLen);
				if(rsp[0] == 0x01){	// length만 전달 된 경우
					retry_flag = true;
				}
				if(nRet < 0) return nRet;
				break;
			}
		}
	}
	else{
		*rspLen = exchangeRspLen;
	}
	*/
	return nRet;
}

smStatus_t i2c_transaction_apdu(struct KoseSession * pSession, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen)
{
	int32_t slotno = 0;
    int32_t out_len = 0;
    smStatus_t retStatus = SM_NOT_OK;
	SE_Connect_Ctx_t *pAuthCtx      = NULL;
	int i2c_address;
	int nRet = 0;
	uint8_t temp_rsp[BUFFER_MAX] = {0};
    size_t temp_rsp_len = 0;

	pAuthCtx = (SE_Connect_Ctx_t *)pSession->conn_ctx;
	i2c_address = pSession->i2c_addr;
	
	//LOGD(TAG, "i2c_address : %d", i2c_address);
	//kss_debug_showframe(TAG, cmdBuf, cmdBufLen);
	//kss_debug_showframe(TAG, temp_rsp, *rspLen);
	nRet = i2c_transaction_set_apdu(i2c_address, cmdBuf, cmdBufLen, temp_rsp, rspLen);
	if (nRet < 0) return retStatus;

	scms++;
	if(scms > 7){
		scms = 0;
	}

	if(retry_flag == true)	// get status 이후 length값을 받아왔다면
	{
		rspLen = temp_rsp[1];
		//LOGD(TAG, "rspLen : %d", rspLen);
		nRet = i2c_transaction_set_apdu(i2c_address, cmdBuf, cmdBufLen, temp_rsp, rspLen);
		if (nRet < 0) return retStatus;

		scms++;
		if(scms > 7){
			scms = 0;
		}
		retry_flag = false;
	}

	*rspLen = (size_t)(*rspLen - 2);
	memcpy(rsp, temp_rsp + 2, *rspLen);
	    
	retStatus = (rsp[*rspLen - 2] << 8) | rsp[*rspLen - 1];
/*
    if (cmdBufLen > INT32_MAX) {
        return retStatus;
    } else {
        if(DE_SAM_apdu(slotno, cmdBufLen, cmdBuf, &out_len, rsp) ==  0x00){
            *rspLen = (size_t)out_len;
            retStatus = (rsp[out_len - 2] << 8) | rsp[out_len - 1];
            if ((rsp[out_len - 2] == 0x61)) {
                uint8_t le = rsp[out_len - 1];
                uint8_t get_resp_apdu[5] = {0x00, 0xC0, 0x00, 0x00, le};
                uint8_t temp_rsp[258] = {0};
                size_t temp_rsp_len = 0;

                if (DE_SAM_apdu(slotno, sizeof(get_resp_apdu), get_resp_apdu, &out_len, temp_rsp) == 0x00) {
                    size_t main_data_len = out_len - 2;
                    if ((*rspLen) + main_data_len < *rspLen) {
                        return SM_NOT_OK;
                    }
                    memcpy(rsp + (*rspLen - 2), temp_rsp, main_data_len + 2);
                    *rspLen = (*rspLen - 2) + main_data_len + 2;
                    retStatus = (temp_rsp[out_len - 2] << 8) | temp_rsp[out_len - 1];
                }
            }
            else if ((rsp[out_len - 2] == 0x6C)) {
				uint8_t sndbuf2[5];
				memcpy(sndbuf2, cmdBuf, 5);
				sndbuf2[4] = rsp[out_len - 2];
				if (DE_SAM_apdu(slotno, cmdBufLen, sndbuf2, &out_len, rsp) == 0x00) {
                }
			}
            return retStatus;
        }
    }
*/
	return retStatus;
}

void kss_kose_i2c_close(kss_kose_session_t *session){
    LOGD(TAG, "kss_kose_i2c_close start");
	se_i2c_close(session->s_ctx.i2c_addr);
}
