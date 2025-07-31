/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2019 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    smartcard.c
//! @brief   Smartcard processing module
/////////////////////////////////////////////////////////////////////////////
#ifdef ESP_PLATFORM
#include "smartcard.h"



/////////////////////////////////////////////////////////////////////////////
// rcv = [3b 9b 96 80 3f c7 a0 80 31 e0 73 fe 21 1b 4b 45 22 20 3f](19)
//
// snd = [00 a4 04 00 01](5)
// rcv = [00 a4 04 00 01 a4](6)
// snd = [a0](1)
// rcv = [a0 61 12](3)
//
// snd = [00 c0 00 00 12](5)
// rcv = [00 c0 00 00 12 c0 6f 10 84 08 a0 00 00 00 03 00 00 00 a5 04 9f 65 01 ff 90 00](26)
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

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
ledc_timer_config_t ledc_timer = {
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

/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////
uart_port_t SCR_UART_PORT_NUM;
//uint8_t *rcvbuf;
//int rcvlen;




/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

uint8_t atr_fd = 0x11;    //!< F/D index
uint8_t atr_protocol = 0; //!< T=0/T=1
uint8_t atr_ifsc = 32;    //!< IFSC




/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드에 전원을 공급하는 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_vcc_init(void)
{
	; // do nothing
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드에 전원을 공급/차단한다.
//! @param[in] on : 전원 on/off 여부. 1=on, 0=off
/////////////////////////////////////////////////////////////////////////////

void smartcard_vcc_ctrl(int on)
{
	; // do nothing
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 리셋 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_rst_init(void)
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
{
	ledc_timer_config(&kose_uart_init_config.ledc_timer);
	ledc_channel_config(&kose_uart_init_config.ledc_channel);    
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 클럭의 on/off 여부를 제어한다.
//! @param[in] ctrl : 클럭 on/off 여부. 1=on, 0=off
/////////////////////////////////////////////////////////////////////////////

void smartcard_clk_ctrl(int ctrl)
{
	if (ctrl) {
		ledc_channel.duty = 1;
	}
	else {
		ledc_channel.duty = 0;
	}

	ledc_set_duty(ledc_channel.speed_mode, ledc_channel.channel, ledc_channel.duty);
	ledc_update_duty(ledc_channel.speed_mode, ledc_channel.channel);
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 IO 핀을 초기화한다.
/////////////////////////////////////////////////////////////////////////////

void smartcard_io_init(kss_kose_uart_ctx_t kose_uart_init_config)
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
	uart_driver_install(kose_uart_init_config.se_uart_pin.se_uart_port_num, kose_uart_init_config.se_uart_pin.se_uart_buff_size * 2, 0, 0, NULL, intr_alloc_flags);
	ESP_ERROR_CHECK(uart_param_config(kose_uart_init_config.se_uart_pin.se_uart_port_num, &uart_config));
	ESP_ERROR_CHECK(uart_set_pin(kose_uart_init_config.se_uart_pin.se_uart_port_num, kose_uart_init_config.se_uart_pin.se_uart_txd, 
		kose_uart_init_config.se_uart_pin.se_uart_rxd, kose_uart_init_config.se_uart_pin.se_uart_rts, kose_uart_init_config.se_uart_pin.se_uart_cts));

	SCR_UART_PORT_NUM = kose_uart_init_config.se_uart_pin.se_uart_port_num;
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 IO 핀을 재초기화한다. (속도 변경)
//! @param[in] fd FD 값
/////////////////////////////////////////////////////////////////////////////

void smartcard_io_reinit(uint8_t fd)
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
	if (sndlen > 0) kss_debug_showframe("c-tpdu", sndbuf, sndlen);
	// ATR
	if (sndlen == 0) {
		int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 32, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		kss_debug_showframe("r-tpdu", rcvbuf, len);
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
		//kss_debug_showframe("sndbuf", sndbuf, 4);
		uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[0], 4);
		uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 4, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 4, 500 / portTICK_PERIOD_MS);
		//kss_debug_showframe("rcvbuf", rcvbuf, len);
		kss_debug_showframe("r-tpdu", rcvbuf, len);
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
		//kss_debug_showframe("sndbuf", sndbuf, 5);
		uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[0], 5);
		uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 5, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		// (2) receive INS || NULL || SW
		for (int loop = 0; ; loop++) {
			int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 1, 5 / portTICK_PERIOD_MS);
			if (len > 0) {
				//kss_debug_showframe("rcvbuf", rcvbuf, len);
				if (rcvbuf[0] == sndbuf[1]) break; // INS
				else if (rcvbuf[0] == 0x60) loop = 0; // NULL
				else if (((rcvbuf[0] & 0xf0) == 0x60) || ((rcvbuf[0] & 0xf0) == 0x90)) { // SW
					len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[1], 1, 5 / portTICK_PERIOD_MS);
					*rcvlen = 2;
					kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return true;
				}
			}
			else {
				if (loop == (10000 - 1)) {
					kss_debug_showframe("r-tpdu", rcvbuf, 0);
					return false;
				}
				else if(len == -1){
					return false;
				}
			}
		}
		// (3) send command data
		if (sndlen > 5) {
			uart_write_bytes(SCR_UART_PORT_NUM, &sndbuf[5], sndlen - 5);
			uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], sndlen - 5, 500 / portTICK_PERIOD_MS); // 시간 조절 필요
		}
		// (4) receive response data + SW
		if (sndlen > 5) {
			int len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], 2, 1000 / portTICK_PERIOD_MS);
			if (len >= 2) {
				*rcvlen = 2;
				kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
				return true;
			}
			else {
				*rcvlen = len;
				kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
				return false;
			}
		}
		else {
			int len = 0;
			if(sndbuf[4] == 0x00){
				sndbuf[4] = 0xFF;
				len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], sndbuf[4] + 3, 1000 / portTICK_PERIOD_MS);
			}
			else{
				len = uart_read_bytes(SCR_UART_PORT_NUM, &rcvbuf[0], sndbuf[4] + 2, 1000 / portTICK_PERIOD_MS);
			}
			//kss_debug_showframe("rcvbuf", rcvbuf, len);
			if (len >= 2) {
				*rcvlen = len;
				if (((rcvbuf[len - 2] & 0xf0) == 0x60) || ((rcvbuf[len - 2] & 0xf0) == 0x90)) {
					kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return true;
				}
				else {
					kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
					return false;
				}
			}
			else {
				*rcvlen = len;
				kss_debug_showframe("r-tpdu", rcvbuf, *rcvlen);
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

	kss_debug_showframe((char *)"ATR", atr, len);
	kss_debug_printf("    TS %02x\n", atr[0]);
	kss_debug_printf("    T0 %02x\n", atr[1]);

	historical_len = atr[index] & 0x0f;
	if (yi & 0x10) { // TA1
		atr_fd = atr[++index];
		kss_debug_printf("    TA1 FD=%02x\n", atr_fd);
	}
	if (yi & 0x20) { // TB1
		index++;
		kss_debug_printf("    TB1 %02x\n", atr[index]);
	}
	if (yi & 0x40) { // TC1
		index++;
		kss_debug_printf("    TC1 %02x\n", atr[index]);
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
		kss_debug_printf("    TD1 T=%d\n", atr[index] & 0x0f);
		if (yi & 0x10) { // TA2
			index++;
			kss_debug_printf("    TA2 %02x\n", atr[index]);
		}
		if (yi & 0x20) { // TB2
			index++;
			kss_debug_printf("    TB2 %02x\n", atr[index]);
		}
		if (yi & 0x40) { // TC2
			index++;
			kss_debug_printf("    TC2 %02x\n", atr[index]);
		}
		if (yi & 0x80) { // TD2
			yi = atr[++index] & 0xf0;
			if (((atr[index] & 0x0f) == 1) || ((atr[index] & 0x0f) == 15)) {
				if (atr_protocol != 1) atr_protocol = atr[index] & 0x0f;
			}
			kss_debug_printf("    TD2 T=%d\n", atr[index] & 0x0f);
			if (yi & 0x10) { // TA3
				if (atr_protocol == 1) {
					atr_ifsc = atr[++index];
					kss_debug_printf("    TA3 IFSC=%d\n", atr_ifsc);
				}
				else {
					kss_debug_printf("    TA3 %02x\n", atr[index]);
				}
			}
			if (yi & 0x20) { // TB3
				index++;
				kss_debug_printf("    TB3 %02x\n", atr[index]);
			}
			if (yi & 0x40) { // TC3
				index++;
				kss_debug_printf("    TC3 %02x\n", atr[index]);
			}
		}
	}
	// T1~Tn
	{
		char tmpbuf[128] = "";
		index++;
		for (int i = 0; i < historical_len; i++) sprintf(&tmpbuf[i * 3], "%02x ", atr[index + i]);
		kss_debug_printf("    T1K %s\n", tmpbuf);
		index += historical_len;
	}
	// TCK
	if (atr_protocol) {
		kss_debug_printf("    TCK %02x\n", atr[index]);
	}
	// result
	{
		kss_debug_printf("- FD = 0x%02x\n", atr_fd);
		kss_debug_printf("- PROTOCOL = %d\n", atr_protocol);
		kss_debug_printf("- IFSC = 0x%02x\n", atr_ifsc);
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
}

/////////////////////////////////////////////////////////////////////////////
//! @brief pps exchange
//! @param[in] rcvbuf : receive 버퍼
//! @param[in] rcvlen : receive 길이
/////////////////////////////////////////////////////////////////////////////
bool smartcard_pps_exchange(uint8_t *rcvbuf, int rcvlen){
	bool ret = false;
	uint8_t sndbuf[] = "\xff\x10\x11\x00";
	sndbuf[2] = atr_fd = 0x96;
	sndbuf[3] = sndbuf[0] ^ sndbuf[1] ^ sndbuf[2];
	ret = smartcard_transceive(sndbuf, 4, rcvbuf, &rcvlen);
	smartcard_io_reinit(atr_fd);
	return ret;
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 함수 테스트
/////////////////////////////////////////////////////////////////////////////

void smartcard_test(void)
{
	//uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU
	//int rcvlen;

	// 포트 초기화
	/*
	{
		smartcard_vcc_init();
		smartcard_rst_init();
		smartcard_clk_init();
		smartcard_io_init();
	}

	// ATR
	{
		smartcard_activate();
		smartcard_transceive((uint8_t *)"", 0, rcvbuf, &rcvlen);
		smartcard_atr_parser(rcvbuf, rcvlen);
	}

	// pps exchange
	{
		uint8_t sndbuf[] = "\xff\x10\x11\x00";
		sndbuf[2] = atr_fd = 0x96;
		sndbuf[3] = sndbuf[0] ^ sndbuf[1] ^ sndbuf[2];
		smartcard_transceive(sndbuf, 4, rcvbuf, &rcvlen);
		smartcard_io_reinit(atr_fd);
	}

	// select a0
	{
		// int rcvlen;
		// smartcard_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen);
		// smartcard_transceive((uint8_t *)"\x00\xc0\x00\x00\x12", 5, rcvbuf, &rcvlen);
	}

	// select a0
	{
		int rcvlen;
		smartcard_apdu((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen);
	}

	free(rcvbuf);
	*/
}


/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 태스크
//! @param[in] arg 태스크 파라미터
/////////////////////////////////////////////////////////////////////////////

void smartcard_task(void *arg)
{
	vTaskDelay(pdMS_TO_TICKS(500));
    //ESP_LOGD(TAG, "");
    //ESP_LOGD(TAG, "smartcard_task() =====");
	LOGI(TAG, "smartcard_task() =====");
	smartcard_test();
	while (1) {
		vTaskDelay(pdMS_TO_TICKS(50));
	}
}

/////////////////////////////////////////////////////////////////////////////
//! @brief 스마트카드 태스크 생성
/////////////////////////////////////////////////////////////////////////////

void smartcard_task_create(void)
{
    xTaskCreate(smartcard_task, "smartcard_task", 4096, NULL, 1, NULL);
}

#endif	// ESP_PLATFORM