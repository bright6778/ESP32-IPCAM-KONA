//
// Created by vnbk on 1/16/23.
//
#include "de_api_sam.h"
// #include "de_api_common.h"
#include "de_err.h"
// #include "de_cmd.h"

// #include "core/common/de_core_common.h"

// #include "bsp/de_bsp.h"


//#include <STDIO.H>

#include "global.h"

struct sc_transact{
	int channel;
	int ispower5v;
	unsigned char *tx_buf;
	unsigned int tx_len;
	unsigned char *rx_buf;
	unsigned int rx_len;
};

#define SC_IOC_MAGIC		's'
#define SC_IOC_MAXNR		5

#define SC_IOC_ACTIVATE			_IOW(SC_IOC_MAGIC, 0,unsigned int *)
#define SC_IOC_READATR			_IOWR(SC_IOC_MAGIC, 1, unsigned int *)
#define SC_IOC_DEACTIVATE		_IOW(SC_IOC_MAGIC, 2,unsigned int *)
#define SC_IOC_GETSTATUS		_IOWR(SC_IOC_MAGIC, 3, unsigned int *)
#define SC_IOC_SETPARAM			_IOW(SC_IOC_MAGIC, 4,unsigned int *)
#define SC_IOC_TRANSACT			_IOWR(SC_IOC_MAGIC, 5, unsigned int *)
#define HWSAM_VERSION			_IOR(SC_IOC_MAGIC, 99, unsigned int *)
#define CTRL_HWSAM_DEBUG		_IOW(SC_IOC_MAGIC, 98,unsigned int *)

static int g_sam_device = -1;
#define SAM_DEVICE_PATH "/dev/devsc"

int32_t DE_BSP_SAM_init(){
	if(g_sam_device > 0){
		printf("SAM device file is open already\n");
		return g_sam_device;
	}
	int fd = open(SAM_DEVICE_PATH, O_RDWR | O_NDELAY | O_NOCTTY);
	if (fd < 0) {
		printf("Open Sam device file is FAILURE\n");
		return -1;
	}
	g_sam_device = fd;
	return g_sam_device;

}
void DE_BSP_SAM_free(){
    if(g_sam_device > 0){
        close(g_sam_device);
    }
    g_sam_device = -1;
}

int32_t DE_BSP_SAM_get_driver_version(char* _version){

	unsigned char DRIVER_Version[20];
	int ret = 0;
	if (g_sam_device < 0)
		return g_sam_device;
	memset(DRIVER_Version, 0, sizeof(DRIVER_Version));
	ret = ioctl(g_sam_device, HWSAM_VERSION, &DRIVER_Version);
	if (ret < 0) {
		memcpy(DRIVER_Version, "Version fail", sizeof("Version fail"));
	}
	memcpy(_version, DRIVER_Version, sizeof(DRIVER_Version));
	return ret;
}


int32_t DE_BSP_SAM_PowerOn(int32_t slotno,int32_t ispower5v, int32_t *outlen, uint8_t* lpRes) {
	struct sc_transact sc_t;
	int i, len;
	unsigned char inbuf[100];
	if (g_sam_device < 0)
		return g_sam_device;
	sc_t.channel = slotno;
	sc_t.ispower5v = ispower5v;
	sc_t.tx_buf = NULL;
	sc_t.rx_buf = inbuf;
	sc_t.tx_len = 0;

	if (g_sam_device < 0)
		return g_sam_device;
	if (ioctl(g_sam_device, SC_IOC_ACTIVATE, &sc_t) < 0) {
		//printf("read/write error\n");
		outlen[0] = 0;
		return 2;
	}
	outlen[0] = sc_t.rx_len;
	//lpRes[0] = 0;
	for (i = 0; i < sc_t.rx_len; i++) {
		lpRes[i] = inbuf[i];

	}

	return 0;
}
int32_t DE_BSP_SAM_PowerOff(int32_t slotno){
	int len;
	if (g_sam_device < 0)
		return g_sam_device;
	len = ioctl(g_sam_device, SC_IOC_DEACTIVATE, &slotno);

	if (len < 0) {
		printf("SC_IOC_DEACTIVATE failed\n");
		return 2;
	}
	return 0;
}
int32_t DE_BSP_SAM_APDU(int32_t slotno, int32_t datalen, uint8_t *data,int32_t *outlen, uint8_t *lpRes) 
{
	struct sc_transact sc_t;
	unsigned char inbuf[256];
	int i;
	if (g_sam_device < 0){
		printf("g_sam_device < 0)\n");
		return g_sam_device;
	}
	sc_t.channel = slotno;
	sc_t.tx_buf = data;
	sc_t.rx_buf = inbuf;
	sc_t.tx_len = datalen;
	if (ioctl(g_sam_device, SC_IOC_TRANSACT, &sc_t) < 0) {
		printf("read/write error\n");
		outlen[0] = 0;
		return 2;
	}
	outlen[0] = sc_t.rx_len;
	for (i = 0; i < sc_t.rx_len; i++) {
		lpRes[i] = inbuf[i];

	}
	return 0;
}




#define _DE_CARD_PON				0xC0
#define _DE_CARD_CASE1				0xC1
#define _DE_CARD_CASE2				0xC2
#define _DE_CARD_CASE3				0xC3
#define _DE_CARD_CASE4				0xC4
#define _DE_CARD_POFF				0xC5
#define _DE_CARD_T1BYPASS			0xC7
#define _DE_CARD_SPEED				0xC8
#define _DE_CARD_APDU				0xC9
#define _DE_CARD_PARITY_ERROR_TEST  		0xCA

int32_t DE_BSP_SAM_Polling(int32_t datalen, uint8_t *data, int32_t *outlen, uint8_t *lpRes)
{
	switch(data[0]){
		case _DE_CARD_PON:
			if(datalen > 2 ) return(DE_BSP_SAM_PowerOn((int)data[1],(int)data[2], outlen,lpRes));
			else {
				*outlen = 0;
				return 61;
			}
			break;
		case _DE_CARD_POFF:
			if(datalen > 1 ) {
				*outlen = 0;
				return(DE_BSP_SAM_PowerOff((int)data[1]));
			}else {
				*outlen = 0;
				return 61;
			}
			break;
		case _DE_CARD_CASE4:
			if(datalen >= 6 ) {
				return(DE_BSP_SAM_APDU((int)data[1],datalen-2,data+2,outlen,lpRes));
			}else {
				*outlen = 0;
				return 61;
			}
			break;
		default:
			*outlen = 0;
			return 17;
	}
}


int32_t DE_SAM_init(){
    return DE_BSP_SAM_init() < 0 ? DE_ERR_NO_INIT : DE_ERR_NONE;
}

int32_t DE_SAM_free(){
    DE_BSP_SAM_free();
    return DE_ERR_NONE;
}
int32_t DE_SAM_on(int32_t slotno,int32_t ispower5v, int32_t *atr_len, uint8_t* atr_data){
    return DE_BSP_SAM_PowerOn(slotno, ispower5v, atr_len, atr_data);
}

int32_t DE_SAM_off(int32_t slotno){
    return DE_BSP_SAM_PowerOff(slotno);
}


int32_t DE_SAM_polling(int32_t _data_len, uint8_t* _data, int32_t* _out_len, uint8_t* _response){
    return DE_BSP_SAM_Polling(_data_len, _data, _out_len, _response);
}
int32_t DE_SAM_apdu(int32_t slotno, int32_t _data_len, uint8_t* _data, int32_t* _out_len, uint8_t* _response){
    return DE_BSP_SAM_APDU(slotno,  _data_len,  _data,_out_len, _response);
}

/***************************************** END ****************************************************/

