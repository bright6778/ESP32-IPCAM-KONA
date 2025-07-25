/*
 * KonaSE.c
 *
 */

#ifdef WIN32
#undef UNICODE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kona_se.h"
#include "driver/uart.h"
//#include "default_params.h"

#define PRINTCOMMAND(f,cmd, apduLen) \
		printf(f);\
		for(i=0; i<apduLen; i++) \
		{  \
			printf("%02X ", cmd[i]); \
		}  \
		printf("\n");

#define PRINTRESPONSE(dwRecvLength, pbRecvBuffer)  \
		for(i=0; i<dwRecvLength; i++) \
		{ \
			printf("%02X ", pbRecvBuffer[i]); \
		} \
		printf("\n"); \

#define MAX_RECEIVE_BUFFER_SIZE 260
// LONG rv;
// SCARDCONTEXT hContext;
// LPTSTR mszReaders;
// SCARDHANDLE hCard;
// DWORD dwReaders, dwActiveProtocol, dwRecvLength;
// SCARD_IO_REQUEST pioSendPci;
unsigned long dwRecvLength;
unsigned char pbRecvBuffer[MAX_RECEIVE_BUFFER_SIZE];
unsigned char getResponseCMD[] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };

unsigned char isdCMD[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
unsigned char iinCMD[] = { 0x80, 0xCA, 0x00, 0x42, 0x00 };
unsigned char cinCMD[] = { 0x80, 0xCA, 0x00, 0x45, 0x00 };
unsigned char cplcCMD[] = { 0x00, 0xCA, 0x9F, 0x7F, 0x00 };

static const char *TAG = "SCR";


/////////////////////////////////////////////////////////////////////////////
// RST 핀 정의
/////////////////////////////////////////////////////////////////////////////

#define SCR_RST_PIN (10)


/////////////////////////////////////////////////////////////////////////////
// CLK 핀 정의 (PWM 설정)
/////////////////////////////////////////////////////////////////////////////

#define SCR_PWM_CHANNEL   LEDC_CHANNEL_0
#define SCR_PWM_TIMER     LEDC_TIMER_0
#define SCR_PWM_OUTPUT_IO (8)                 // 사용할 GPIO 핀 번호 (5:ok, 8:ok, 9:fail)
#define SCR_PWM_FREQUENCY (3579545)           // PWM 주파수 (Hz)
#define SCR_PWM_DUTY_RES  LEDC_TIMER_1_BIT    // 1비트 해상도
#define SCR_PWM_DUTY      (2 - 1)             // 최대 듀티 사이클

// LEDC 타이머 설정
/*ledc_timer_config_t ledc_timer = {
	.speed_mode = LEDC_LOW_SPEED_MODE,
	.timer_num = SCR_PWM_TIMER,
	.duty_resolution = SCR_PWM_DUTY_RES,
	.freq_hz = SCR_PWM_FREQUENCY,
	.clk_cfg = LEDC_AUTO_CLK
};

// LEDC 채널 설정
ledc_channel_config_t ledc_channel = {
	.speed_mode = LEDC_LOW_SPEED_MODE,
	.channel = SCR_PWM_CHANNEL,
	.timer_sel = SCR_PWM_TIMER,
	.intr_type = LEDC_INTR_DISABLE,
	.gpio_num = SCR_PWM_OUTPUT_IO,
	.duty = 1,                          // 초기 듀티 사이클
	.hpoint = 0,
};
*/

/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////
//uart_port_t SCR_UART_PORT_NUM;
//uint8_t *rcvbuf;
//int rcvlen;




/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

/*uint8_t atr_fd = 0x11;    //!< F/D index
uint8_t atr_protocol = 0; //!< T=0/T=1
uint8_t atr_ifsc = 32;    //!< IFSC*/
kss_kose_uart_ctx_t kose_uart_init_config;


/**
 * This method is used to retrieve Secure Element ID (SEID) from Smart Card.
 *
 * @param se_id This parameter used to receive SEID from Smart Card.
 * @param se_id_len This returns the length of SEID.
 * @return int status of the access to SEID from card
 */
int get_se_id(char** se_id, int *se_id_len) {

	//init_se();

	unsigned char response[1000];
	int res_len, i;
	int offset = 0;
	res_len = 0;

	(*se_id) = (char*) malloc(40);
	char* temp_se_id = (char*)malloc(20);

	int ret = smartcard_apdu(isdCMD, 5 ,response,&res_len);
	if(ret < 0) {
		return -1;
	}

	// reset res_len otherwise SEID length will be greater than expected. Bug - Need to fix it,
	// the meaning of res_len in send_command function is not proper
	res_len = 0;
	ret = smartcard_apdu(iinCMD, 5, response, &res_len);
	if(ret < 0) {
		return -1;
	}

	int idLen = (response[1] & 0x00FF);
	for (i = 0; i < idLen; i++) {
		sprintf((*se_id)+(offset*2),"%02X",response[2 + i]);
		offset++;
	}

	res_len = 0;
	ret = smartcard_apdu(cinCMD, 5, response, &res_len);

	idLen = (response[1] & 0x00FF);
	for (i = 0; i < idLen; i++) {
		sprintf((*se_id)+(offset*2),"%02X",response[2 + i]);
		offset++;
	}

	printf("\nSEID: %s", (*se_id));

	printf("\n\n");
	//close_se();
	*se_id_len = (offset*2);

	/**se_id = SE_ID;
	*se_id_len = 22;*/

	return 0;
}

/**
 * This method is used to retrieve CPLC from Smart Card.
 *
 * @param se_id This parameter used to receive CPLC from Smart Card.
 * @return int This returns the length of CPLC
 */
int get_cplc(char** cplc) {

	//	(*cplc) = CPLC;
	//	return 20;
	unsigned char response[256];
	int res_len = 0,i=0 ;
	(*cplc) = (char*)malloc(44*sizeof(char));
	//init_se();
	//int ret = send_command(isdCMD, 5 ,response,&res_len);

	res_len = 0;
	int ret = smartcard_apdu(cplcCMD,5 ,response,&res_len);
	if(ret < 0) {
		return -1;
	}
	for (i = 0; i < 20; i++) {
		sprintf((*cplc)+(i*2),"%02X",response[i]);
	}

	printf("\nCPLC: %s",(*cplc));

	//close_se();

	return 0;
}

/**
 * This method is used to search for existing applet with given AID.
 *
 * @param aid This parameter contain intended AID
 * @param len This is the second parameter that contain AID length
 * @return int This returns status of applet exist or not. 0: applet exist or -1: applet not present
 */
int is_applet_exist(unsigned char* AID, int len){
	unsigned char response[256];
	int rLen = 0;
	unsigned char *command = (unsigned char*)malloc((5+len)*sizeof(unsigned char));

	command[0] = 0x00;
	command[1] = 0xA4;
	command[2] = 0x04;
	command[3] = 0x00;
	command[4] = (unsigned char)(len & 0x00FF);

	memcpy(command + 5, AID, len);

	//init_se(); //Smart Card Reader Connect
	int ret = smartcard_apdu(command, len+5, response, &rLen);
	//close_se(); //Smart Card Reader Disconnect

	return ret;
}
/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드에 전원을 공급하는 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_vcc_init(void)
{
	; // do nothing
}
*/
/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드에 전원을 공급/차단한다.
//! @param[in] on : 전원 on/off 여부. 1=on, 0=off
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_vcc_ctrl(int on)
{
	; // do nothing
}*/

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 리셋 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_rst_init(void)
{
	gpio_set_direction(SCR_RST_PIN, GPIO_MODE_OUTPUT); // 출력 모드로 설정
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 리셋 핀을 high/low 제어한다.
//! @param[in] ctrl : 리셋 on/off 여부. 1=on, 0=off
//! @return None
/////////////////////////////////////////////////////////////////////////////

void smartcard_rst_ctrl(int ctrl)
{
	gpio_set_level(SCR_RST_PIN, ctrl);
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 클럭 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_clk_init(kss_kose_uart_ctx_t kose_uart_init_config)
//void smartcard_clk_init()
{
	ledc_timer_config(&kose_uart_init_config.ledc_timer);
	ledc_channel_config(&kose_uart_init_config.ledc_channel);    
}*/

/////////////////////////////////////////////////////////////////////////////
//! @brief 클럭의 on/off 여부를 제어한다.
//! @param[in] ctrl : 클럭 on/off 여부. 1=on, 0=off
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_clk_ctrl(int ctrl)
{
	if (ctrl) {
		ledc_channel.duty = 1;
	}
	else {
		ledc_channel.duty = 0;
	}

	ledc_set_duty(ledc_channel.speed_mode, ledc_channel.channel, ledc_channel.duty);
	ledc_update_duty(ledc_channel.speed_mode, ledc_channel.channel);
}*/

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 IO 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_io_init(kss_kose_uart_ctx_t kose_uart_init_config)
//void smartcard_io_init()
{
	uart_config_t uart_config = {
		.baud_rate = kose_uart_init_config.se_uart_pin.se_uart_baud_rate,
		.data_bits = UART_DATA_8_BITS,
		.parity    = UART_PARITY_EVEN,       //UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};
	int intr_alloc_flags = 0;

#if CONFIG_UART_ISR_IN_IRAM
	intr_alloc_flags = ESP_INTR_FLAG_IRAM;
#endif

	//ESP_ERROR_CHECK(uart_driver_install(SCR_UART_PORT_NUM, SCR_UART_BUFF_SIZE * 2, 0, 0, NULL, intr_alloc_flags));
	esp_err_t ret = uart_driver_install(kose_uart_init_config.se_uart_pin.se_uart_port_num, kose_uart_init_config.se_uart_pin.se_uart_buff_size * 2, 0, 0, NULL, intr_alloc_flags);
	ESP_ERROR_CHECK(uart_param_config(kose_uart_init_config.se_uart_pin.se_uart_port_num, &uart_config));
	ESP_ERROR_CHECK(uart_set_pin(kose_uart_init_config.se_uart_pin.se_uart_port_num, kose_uart_init_config.se_uart_pin.se_uart_txd, 
		kose_uart_init_config.se_uart_pin.se_uart_rxd, kose_uart_init_config.se_uart_pin.se_uart_rts, kose_uart_init_config.se_uart_pin.se_uart_cts));

	SCR_UART_PORT_NUM = kose_uart_init_config.se_uart_pin.se_uart_port_num;
}
*/
/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 IO 핀을 재초기화한다. (속도 변경)
//! @param[in] fd FD 값
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_io_reinit(uint8_t fd)
{
	const uint16_t F_table[16] = {
			372, 372, 558, 744, 1116, 1488, 1860, 0,
			0, 512, 768, 1024, 1536, 2048, 0, 0
	};
	const uint8_t D_table[8] = {
			0, 1, 2, 4, 8, 16, 32, 64
	};

	int baudrate = 9600;
	int F = F_table[(fd >> 4) & 0x0f];
	int D = D_table[(fd >> 0) & 0x0f];
	switch (fd) {
	// case 0x11 : baudrate = 9600; break;
	// case 0x12 : baudrate = 19200; break;
	// case 0x13 : baudrate = 38400; break;
	// case 0x96 : baudrate = 223200; break;
	default : baudrate = SCR_PWM_FREQUENCY * D / F; break;
	}
	uart_config_t uart_config = {
		.baud_rate = baudrate,
		.data_bits = UART_DATA_8_BITS,
		.parity    = UART_PARITY_EVEN,       //UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};

	ESP_ERROR_CHECK(uart_param_config(SCR_UART_PORT_NUM, &uart_config));
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드를 activation 한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_activate(void)
{
	smartcard_vcc_ctrl(1);
	smartcard_rst_ctrl(0);
	vTaskDelay(pdMS_TO_TICKS(50));
	smartcard_rst_ctrl(1);
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드를 deactivation 한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_deactivate(void)
{
	smartcard_rst_ctrl(0);
	smartcard_vcc_ctrl(0);
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드를 warm reset 한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_warm_reset(void)
{
	smartcard_rst_ctrl(0);
	vTaskDelay(pdMS_TO_TICKS(50));
	smartcard_rst_ctrl(1);
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드로 C-TPDU를 보내고, R-TPDU를 받는다.
//! @param[in] sndbuf C-TPDU 버퍼
//! @param[in] sndlen C-TPDU 길이
//! @param[out] rcvbuf R-TPDU 버퍼 (loopback을 고려한 충분한 크기)
//! @param[out] rcvlen R-TPDU 길이
/////////////////////////////////////////////////////////////////////////////

bool smartcard_transceive(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen)
{
	if (sndlen > 0) debug_showframe("c-tpdu", sndbuf, sndlen);
	// ATR
	if (sndlen == 0) {
		int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 32, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		debug_showframe("r-tpdu", rcvbuf, len);
		if (len > 3) {
			*rcvlen = len;
			return true;
		}
		else {
			*rcvlen = 0;
			return false;
		}
	}
	// PPS exchange
	else if (sndlen == 4) {
		debug_showframe("sndbuf", sndbuf, 4);
		uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[0], 4);
		uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 4, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 4, 500 / portTICK_PERIOD_MS);
		debug_showframe("rcvbuf", rcvbuf, len);
		debug_showframe("r-tpdu", rcvbuf, len);
		if (len == 4) {
			*rcvlen = len;
			return true;
		}
		else {
			*rcvlen = 0;
			return false;
		}
	}
	// TPDU
	else {
		// (1) send command header
		debug_showframe("sndbuf", sndbuf, 5);
		uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[0], 5);
		uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 5, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		// (2) receive INS || NULL || SW
		for (int loop = 0; ; loop++) {
			int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 1, 5 / portTICK_PERIOD_MS);
			if (len > 0) {
				debug_showframe("rcvbuf", rcvbuf, len);
				if (rcvbuf[0] == sndbuf[1]) break; // INS
				else if (rcvbuf[0] == 0x60) loop = 0; // NULL
				else if (((rcvbuf[0] & 0xf0) == 0x60) || ((rcvbuf[0] & 0xf0) == 0x90)) { // SW
					len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[1], 1, 5 / portTICK_PERIOD_MS);
					*rcvlen = 2;
					debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return true;
				}
			}
			else {
				if (loop == (10000 - 1)) {
					debug_showframe("r-tpdu", rcvbuf, 0);
					return false;
				}
				else if(len == -1){
					return false;
				}
			}
		}
		// (3) send command data
		if (sndlen > 5) {
			debug_showframe("sndbuf", &sndbuf[5], sndlen - 5);
			uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[5], sndlen - 5);
			uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], sndlen - 5, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		}
		// (4) receive response data + SW
		if (sndlen > 5) {
			int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 2, 1000 / portTICK_PERIOD_MS);
			debug_showframe("rcvbuf", rcvbuf, len);
			if (len >= 2) {
				*rcvlen = 2;
				debug_showframe("r-tpdu", rcvbuf, *rcvlen);
				return true;
			}
			else {
				*rcvlen = len;
				debug_showframe("r-tpdu", rcvbuf, *rcvlen);
				return false;
			}
		}
		else {
			int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], sndbuf[4] + 2, 1000 / portTICK_PERIOD_MS);
			debug_showframe("rcvbuf", rcvbuf, len);
			if (len >= 2) {
				*rcvlen = len;
				if (((rcvbuf[len - 2] & 0xf0) == 0x60) || ((rcvbuf[len - 2] & 0xf0) == 0x90)) {
					debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return true;
				}
				else {
					debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return false;
				}
			}
			else {
				*rcvlen = len;
				debug_showframe("r-tpdu", rcvbuf, *rcvlen);
				return false;
			}
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드로 C-APDU를 보내고, R-APDU를 받는다.
//! @param[in] sndbuf C-APDU 버퍼
//! @param[in] sndlen C-APDU 길이
//! @param[out] rcvbuf R-APDU 버퍼 (loopback을 고려한 충분한 크기)
//! @param[out] rcvlen R-APDU 길이
/////////////////////////////////////////////////////////////////////////////

bool smartcard_apdu(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen)
{
	bool ret;
	// case 1
	if (sndlen == 4) {
		uint8_t sndbuf2[5];
		memset(sndbuf2, 0, sizeof(sndbuf2));
		memcpy(sndbuf2, sndbuf, 4);
		ret = smartcard_transceive(sndbuf2, 5, rcvbuf, rcvlen);
	}
	else {
		ret = smartcard_transceive(sndbuf, sndlen, rcvbuf, rcvlen);
	}
	// 61/6c
	if (ret) {
		if (*rcvlen == 2) {
			if (rcvbuf[*rcvlen - 2] == 0x61) {
				uint8_t sndbuf2[] = "\x00\xc0\x00\x00\x00";
				sndbuf2[0] = sndbuf[0];
				sndbuf2[4] = rcvbuf[*rcvlen - 1];
				ret = smartcard_transceive(sndbuf2, 5, rcvbuf, rcvlen);
			}
			else if (rcvbuf[*rcvlen - 2] == 0x6c) {
				uint8_t sndbuf2[5];
				memcpy(sndbuf2, sndbuf, 5);
				sndbuf2[4] = rcvbuf[*rcvlen - 1];
				ret = smartcard_transceive(sndbuf2, 5, rcvbuf, rcvlen);
			}
		}
	}
	return ret;
}

/////////////////////////////////////////////////////////////////////////////
//! @brief ATR을 분석해 필요한 부분을 추출한다.
//! 전체를 파싱하지 않고 필요한 부분만 파싱한다. 추출하는 내용은 다음과 같다.
//! - TA1으로 F/D 추출
//! - TD1, TD2으로 T=0인지 T=1인지 구분
//! - TA3으로 IFSC 추출
//! @param[in] atr : ATR 버퍼
//! @param[in] len : ATR 길이
/////////////////////////////////////////////////////////////////////////////

void smartcard_atr_parser(uint8_t atr[], int len)
{
	// format : TS / T0 / TA1 / TB1 / TC1 / TD1 / TA2 / ... / T1...Tn / TCK

	uint8_t historical_len = 0;
	uint8_t index = 0;
	uint8_t yi = atr[++index] & 0xf0;

	// set default
	{
		atr_fd = 0x11;     //!< F/D index
		atr_protocol = 0;  //!< T=0  / T=1
		atr_ifsc = 0x20;   //!< IFSC
	}

	debug_showframe((char *)"ATR", atr, len);
	debug_printf("    TS %02x\n", atr[0]);
	debug_printf("    T0 %02x\n", atr[1]);

	historical_len = atr[index] & 0x0f;
	if (yi & 0x10) { // TA1
		atr_fd = atr[++index];
		debug_printf("    TA1 FD=%02x\n", atr_fd);
	}
	if (yi & 0x20) { // TB1
		index++;
		debug_printf("    TB1 %02x\n", atr[index]);
	}
	if (yi & 0x40) { // TC1
		index++;
		debug_printf("    TC1 %02x\n", atr[index]);
	}
	if (yi & 0x80) { // TD1
		yi = atr[++index] & 0xf0;
		if (((atr[index] & 0x0f) == 1) || ((atr[index] & 0x0f) == 15)) {
			if ((atr[index] & 0x0f) == 1) {
				atr_protocol = 1;
			}
			else if ((atr[index] & 0x0f) == 15) {
				atr_protocol = 15;
			}
		}
		debug_printf("    TD1 T=%d\n", atr[index] & 0x0f);
		if (yi & 0x10) { // TA2
			index++;
			debug_printf("    TA2 %02x\n", atr[index]);
		}
		if (yi & 0x20) { // TB2
			index++;
			debug_printf("    TB2 %02x\n", atr[index]);
		}
		if (yi & 0x40) { // TC2
			index++;
			debug_printf("    TC2 %02x\n", atr[index]);
		}
		if (yi & 0x80) { // TD2
			yi = atr[++index] & 0xf0;
			if (((atr[index] & 0x0f) == 1) || ((atr[index] & 0x0f) == 15)) {
				if (atr_protocol != 1) atr_protocol = atr[index] & 0x0f;
			}
			debug_printf("    TD2 T=%d\n", atr[index] & 0x0f);
			if (yi & 0x10) { // TA3
				if (atr_protocol == 1) {
					atr_ifsc = atr[++index];
					debug_printf("    TA3 IFSC=%d\n", atr_ifsc);
				}
				else {
					debug_printf("    TA3 %02x\n", atr[index]);
				}
			}
			if (yi & 0x20) { // TB3
				index++;
				debug_printf("    TB3 %02x\n", atr[index]);
			}
			if (yi & 0x40) { // TC3
				index++;
				debug_printf("    TC3 %02x\n", atr[index]);
			}
		}
	}
	// T1~Tn
	{
		char tmpbuf[128] = "";
		index++;
		for (int i = 0; i < historical_len; i++) sprintf(&tmpbuf[i * 3], "%02x ", atr[index + i]);
		debug_printf("    T1K %s\n", tmpbuf);
		index += historical_len;
	}
	// TCK
	if (atr_protocol) {
		debug_printf("    TCK %02x\n", atr[index]);
	}
	// result
	{
		debug_printf("- FD = 0x%02x\n", atr_fd);
		debug_printf("- PROTOCOL = %d\n", atr_protocol);
		debug_printf("- IFSC = 0x%02x\n", atr_ifsc);
	}
}

/////////////////////////////////////////////////////////////////////////////
//! @brief Get ATR
//! @param[in] rcvbuf : ATR 버퍼
//! @param[in] rcvlen : ATR 길이
/////////////////////////////////////////////////////////////////////////////
bool smartcard_getATR(uint8_t *rcvbuf, int rcvlen){
	bool ret = false;
	smartcard_activate();
	ret = smartcard_transceive((uint8_t *)"", 0, rcvbuf, &rcvlen);
	smartcard_atr_parser(rcvbuf, rcvlen);
	return ret;
}*/

/////////////////////////////////////////////////////////////////////////////
//! @brief pps exchange
//! @param[in] rcvbuf : receive 버퍼
//! @param[in] rcvlen : receive 길이
/////////////////////////////////////////////////////////////////////////////
/*bool smartcard_pps_exchange(uint8_t *rcvbuf, int rcvlen){
	bool ret = false;
	uint8_t sndbuf[] = "\xff\x10\x11\x00";
	sndbuf[2] = atr_fd = 0x96;
	sndbuf[3] = sndbuf[0] ^ sndbuf[1] ^ sndbuf[2];
	ret = smartcard_transceive(sndbuf, 4, rcvbuf, &rcvlen);
	smartcard_io_reinit(atr_fd);
	return ret;
}*/

/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////
uint8_t *rcvbuf;
int rcvlen;

bool init_se(){
    bool ret = false;
	kose_uart_init_config.se_uart_pin.se_uart_txd = SE_UART_TXD,
    kose_uart_init_config.se_uart_pin.se_uart_rxd = SE_UART_RXD,
    kose_uart_init_config.se_uart_pin.se_uart_rts = SE_UART_RTS,
    kose_uart_init_config.se_uart_pin.se_uart_cts = SE_UART_CTS,
    kose_uart_init_config.se_uart_pin.se_uart_port_num = UART_NUM_1,
    kose_uart_init_config.se_uart_pin.se_uart_baud_rate = SE_UART_BAUD_RATE,
    kose_uart_init_config.se_uart_pin.se_uart_buff_size = SE_UART_BUFF_SIZE,

    // LEDC 타이머 설정
    kose_uart_init_config.ledc_timer.speed_mode = LEDC_LOW_SPEED_MODE;
    kose_uart_init_config.ledc_timer.timer_num = SCR_PWM_TIMER;
    kose_uart_init_config.ledc_timer.duty_resolution = SCR_PWM_DUTY_RES;
    kose_uart_init_config.ledc_timer.freq_hz = SCR_PWM_FREQUENCY;
    kose_uart_init_config.ledc_timer.clk_cfg = LEDC_AUTO_CLK;
    
    // LEDC 채널 설정
    kose_uart_init_config.ledc_channel.speed_mode = LEDC_LOW_SPEED_MODE;
    kose_uart_init_config.ledc_channel.channel = SCR_PWM_CHANNEL;
    kose_uart_init_config.ledc_channel.timer_sel = SCR_PWM_TIMER;
    kose_uart_init_config.ledc_channel.intr_type = LEDC_INTR_DISABLE;
    kose_uart_init_config.ledc_channel.gpio_num = SCR_PWM_OUTPUT_IO;
    kose_uart_init_config.ledc_channel.duty = 1;
    kose_uart_init_config.ledc_channel.hpoint = 0;
   // smartcard_vcc_init();
   // smartcard_rst_init();
   // smartcard_clk_init(kose_uart_init_config);
    //smartcard_io_init(kose_uart_init_config);
    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU
    ret = smartcard_getATR(rcvbuf, rcvlen);
    if (ret == false){
        free(rcvbuf);
        rcvbuf = NULL;
        return ret;
    } 
    ret = smartcard_pps_exchange(rcvbuf, rcvlen);
    return ret;
}

void close_se(){
    //LOGI(TAG, "kss_kose_uart_close start");
    ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
    uart_driver_delete(UART_NUM_1);
    uart_set_pin(UART_NUM_1, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    if(rcvbuf != NULL){
        //LOGD(TAG, "free");
        free(rcvbuf);
        rcvbuf = NULL;
    }  
}
/**
 * This method is used to Establish Smart Card Context, Select Smart Card Reader, and Connect with Smart Card
 */
//void init_se() {

// 	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
// 	CHECK("SCardEstablishContext", rv)

// #ifdef SCARD_AUTOALLOCATE
// 	dwReaders = SCARD_AUTOALLOCATE;

// 	rv = SCardListReaders(hContext, NULL, (LPTSTR) &mszReaders, &dwReaders);
// 	CHECK("SCardListReaders", rv)
// #else
// 	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
// 	CHECK("SCardListReaders", rv)

// 	mszReaders = calloc(dwReaders, sizeof(char));
// 	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
// 	CHECK("SCardListReaders", rv)
// #endif
// 	printf("Reader Name: %s\n", mszReaders); //prints reader name

// 	rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED,
// 			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
// 	CHECK("SCardConnect", rv)

// 	switch (dwActiveProtocol) {
// 	case SCARD_PROTOCOL_T0:
// 		pioSendPci = *SCARD_PCI_T0;
// 		break;

// 	case SCARD_PROTOCOL_T1:
// 		pioSendPci = *SCARD_PCI_T1;
// 		break;
// 	}

//}

/**
 * This method is used to disconnect with Smart Card, free card reader and Release Smart Card Context.
 */
//void close_se() {
// 	//card is disconnected here
// 	rv = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
// 	CHECK("SCardDisconnect", rv)

// #ifdef SCARD_AUTOALLOCATE
// 	rv = SCardFreeMemory(hContext, mszReaders);
// 	CHECK("SCardFreeMemory", rv)

// #else
// 	free(mszReaders);
// #endif

// 	rv = SCardReleaseContext(hContext);

// 	CHECK("SCardReleaseContext", rv)

//}

/**
 * Before calling this method you must need to call @see init_se() and res_len initialized with zero(0).
 *
 * This method is used to transmit command into Smart Card and retrieve corresponding response data.
 *
 * @param apduCMD This parameter is actual apdu command that is transmit into smart card.
 * @param apduLen This parameter is length of apdu command.
 * @param response This is the response parameter that is the receive corresponding response apdu from smart card
 * @param res_len This parameter contain length of response apdu initial value must be set with zero(0)
 *
 * @return int This returns 0 or -1, if command execute success with response SW 9000 then return 0 otherwise -1
 */
// int send_command(unsigned char *apduCMD, int apduLen, unsigned char *response, int *res_len) {

// 	int i, recvDataLen;
// 	dwRecvLength = MAX_RECEIVE_BUFFER_SIZE;

// 	// PRINTCOMMAND("\nT: ", apduCMD, apduLen)
// 	// rv = SCardTransmit(hCard, &pioSendPci, apduCMD, apduLen, NULL, pbRecvBuffer,
// 	// 		&dwRecvLength);
// 	// PRINTCOMMAND("C: ", pbRecvBuffer, dwRecvLength)
// 	// CHECK("SCardTransmit", rv)

// 	//	recvDataLen = dwRecvLength - 2;
//     uart_write_bytes(UART_NUM_0, apduCMD, apduLen);
// 	recvDataLen = dwRecvLength;
// 	if (recvDataLen > 0) {
// 		memcpy(response + (*res_len), pbRecvBuffer, recvDataLen);
// 		(*res_len) += recvDataLen;
// 	}
    
// 	unsigned char sw1 = pbRecvBuffer[dwRecvLength - 2];
// 	unsigned char sw2 = pbRecvBuffer[dwRecvLength - 1];

// 	if (sw1 == 0x90 && sw2 == 0x00) {
// 		//		response[(*res_len)++]=sw1;
// 		//		response[(*res_len)++]=sw2;

// 		return 0;
// 	} else if ((sw1 == 0x61) && sw2 != 0x00) {
// 		(*res_len) -= 2;
// 		getResponseCMD[4] = sw2;
// 		return send_command(getResponseCMD, 5, response, res_len);
// 	} else if ((sw1 == 0x6C) && sw2 != 0x00) {
// 		(*res_len) -= 2;
// 		apduCMD[apduLen-1] = sw2;
// 		return send_command(apduCMD, 5, response, res_len);
// 	} else {
// 		return -1;
// 	}
// }


