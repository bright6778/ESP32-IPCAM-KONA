/**
 * @file de_api_common.h
 * @author thuan@duali.com
 * @date 02/02/2023.
 * @brief This is Common APIs that is supported by Duali Electronic.
 */

#ifndef DE_API_COMMON_H
#define DE_API_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "de_types.h"

/***************************** Duali system API *******************************************/
/**
 * @brief Initialize Duali device.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_init(void);


/**
 * @brief Reboot Duali Device
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_reboot(void);

/**
* @brief Get the device serial.
* @param _serial of device. Ex:
* @return Length of serial value. -1 if the device is not support or not available
*/
int32_t DE_get_product_serial(char* _serial);

/**
* @brief Get product model. Ex: DqMiniPlus.
* @param _model : of product that it is returned.
* @return Length of model value. -1 if the device is not support or not available
*/
int32_t DE_get_product_model(char* _model);

/**
 * @brief Get product version (Hardware version). Ex: MINIPLUS01012023
 * @param _version of product that it is returned.
 * @return Length of _version value. -1 if the device is not support or not available
 */
int32_t DE_get_product_version(char* _version);

/**
 * @brief Get firmware version of product. Ex: dqminiplus-20230101
 * @param _version of product that it is returned.
 * @return Length of _version value. -1 if the device is not support or not available
 */
int32_t DE_get_firmware_version(char* _version);

/**
 * @brief Get kernel version of product if supported. Ex: 3.108.10
 * @param _version of product that it is returned.
 * @return Length of _version value. -1 if the device is not support or not available
 */
int32_t DE_get_kernel_version(char* _version);

/**
 * @brief Delay time in mini seconds
 * @param  _ms is mini seconds.
 * @return NONE
 */
void DE_delay(int32_t _ms);

/**
 * @brief Delay time in micro seconds
 * @param _us is micro seconds.
 * @return NONE
 */
void DE_delay_us(int32_t _us);

/**
 * @brief Get Current tick count in the device. Unit ms.
 * @return Current tick count. -1 if FAILURE.
 */
int32_t DE_get_tick_count(void);

/***************************************************************/
/*                      Duali RTC API                          */
/***************************************************************/

/**
 * @brief Enable and Initialize RTC module if the device support
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RTC_init(void);

/**
 * @brief Released and disable RTC module if the device support
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RTC_free(void);

/**
 * @brief Set date time to RTC module if the device support
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RTC_set_time(de_datetime_t* _datetime);

/**
 * @brief Get date time from RTC module if the device support
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RTC_get_time(de_datetime_t* _datetime);


/***************************************************************/
/*                      Duali Watchdog Timer API               */
/***************************************************************/

/**
 * @brief Enable and Initialize watchdog timer if support.
 * @param _period_ms is the period. _period = 0 is default value.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_WDT_init(int32_t _period_ms);

/**
 * @brief Free resource and disable watchdog timer.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t   DE_WDT_free();

/**
 * @brief Enable the watchdog timer.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_WDT_enable(void);

/**
 * @brief Disable the watchdog timer.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_WDT_disable(void);

/**
 * @brief Reload the watchdog timer.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_WDT_reload(void);


/******************************* Duali Digital Input/Output API **************************/
/**
 * @brief Enable and Initialize digital inputs/outputs of device.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_DIO_init(void);

/**
 * @brief Free resources and disable the digital inputs/outputs.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_DIO_free(void);

/***************************************************************/
/*                      Duali LED Indicator API                */
/***************************************************************/

/**
 * @brief Define all LEDs that the device supports
 */
enum {
    DE_LED_RED = 0, ///< Red LED
    DE_LED_BLUE,    ///< Blue LED
    DE_LED_GREEN,   ///< Green LED
    DE_LED_STATUS,  ///< Status LED
};

/**
 * @brief Turn on the led of devices.
 * @param _led: is led index that is defined above.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_LED_on(uint8_t _led);

/**
 * @brief Turn off the led of devices.
 * @param _led: is led index that is defined above.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_LED_off(uint8_t _led);

/**
 * @brief Blink led.
 * @param _led: is led index that is defined above.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_LED_blink(uint8_t _led);

/**
 * @brief Get led state (1: ON, 0: OFF).
 * @param _led: is led index that is defined above.
 * @return The current led state. -1 if FAILURE.
 */
int32_t DE_LED_get_state(uint8_t _led);

/***************************************************************/
/*                      Duali Input API                        */
/***************************************************************/
/**
 * @brief Get input led that control leds of device.
 * @return 1 if users want to turn on leds. 0 if users want to turn off leds.
 */
int32_t DE_LED_INPUT_get_state(void);

/**
 * @brief Get input beep that control beep of device.
 * @return if users want to turn on beep. 0 if users want to turn off beep.
 */
int32_t DE_BEEP_INPUT_get_state(void);

/**
 * @brief Get case sensor state if the device supported.
 * @return Case sensor state. 1 if case sensor is on. 0 if case sensor is off. -1 if case sensor is not supported
 */
int32_t DE_CASE_SENSOR_get_state(void);

/***************************************************************/
/*                      Duali Tamper API                       */
/***************************************************************/

/**
 * @brief Turn on the tamper if the device supported.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_TAMPER_on(void);

/**
 * @brief Turn off the tamper if the device supported.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_TAMPER_off(void);

/**
 * @brief Get Tamper state if the device supported.
 * @return Tamper state. 1 if Tamper is on. 0 if Tamper is off. -1 if Tamper is not supported
 */
int32_t DE_TAMPER_get_state(void);

/***************************************************************/
/*                      Duali Controller API                   */
/***************************************************************/

/**
 * @brief Get Exit Button state if the device supported.
 * @return Exit Button state. 1 if Exit Button is not pressed. 0 if Exit Button is pressed. -1 if Exit Button is not supported
 */
int32_t DE_EXIT_BT_get_state(void);

/**
 * @brief Get case sensor state if the device supported.
 * @return Case sensor state. 1 if case sensor is on. 0 if case sensor is off. -1 if case sensor is not support
 */
int32_t DE_DOOR_SENSOR_get_state(void);

/**
 * @brief Lock the door if the device supported. Usually for controllers.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_DOOR_lock(void);

/**
 * @brief Unlock the door if the device supported. Usually for controllers.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_DOOR_unlock(void);

/**
 * @brief Get door lock state if the device support.
 * @return Door Lock state. 1 if Door Lock is locked. 0 if Door Lock is unlocked. -1 if Door Lock is not supported
 */
int32_t DE_DOOR_get_state(void);

/**
 * @brief Turn on the Alarm if the device support. Usually for controllers.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_ALARM_on(void);

/**
 * @brief Turn off the Alarm if the device support. Usually for controllers.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_ALARM_off(void);

/**
 * @brief Get the alarm state if the device support.
 * @return Alarm state. 1 if Alarm is turned on. 0 if Alarm is turned off. -1 if Alarm is not supported
 */
int32_t DE_ALARM_get_state(void);

/***************************************************************/
/*                      Duali PDU Clock API                    */
/***************************************************************/

/**
 * @brief Initialized PDU clock if the device support.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE. Please check "Error code" in de_err.h file.
 */
int32_t DE_PDU_init();

/**
 * @brief Freed resources and disable PDU Clock.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE. Please check "Error code" in de_err.h file.
 */
int32_t DE_PDU_free();

/**
 * @brief Enable the PDU Clock.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE. Please check "Error code" in de_err.h file.
 */
int32_t DE_PDU_enable(void);

/**
 * @brief Disable the PDU Clock.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE. Please check "Error code" in de_err.h file.
 */
int32_t DE_PDU_disable(void);

/**
 * @brief Get period of PDU clock. Unit: Hz (Ex. 1000Hz).
 * @return Period of PDU clock. otherwise FAILURE. Please check "Error code" in de_err.h file.
 */
int32_t DE_PDU_get_period(void);


/***************************************************************/
/*                      Duali Wiegand API                      */
/***************************************************************/

/**
 * @brief Define Wiegand channel that device support.
 */
enum {
    DE_WGD_CHANNEL_0, ///< Wiegand Channel 0
    DE_WGD_CHANNEL_1, ///< Wiegand Channel 1
    DE_WGD_CHANNEL_NUMBER = 1 ///< Number of Wiegand Channel.
};

/**
 * @brief Define Wiegand role of wiegand channel.
 */
enum {
    DE_WGD_ROLE_INPUT,  ///< Wiegand Input Role as the Controller.
    DE_WGD_ROLE_OUTPUT, ///< Wiegand Output Role as the Reader. Send Card ID to the Controller.
    DE_WGD_ROLE_DEFAULT = DE_WGD_ROLE_OUTPUT    ///< Default Wiegand Role is Output.
};

/**
 * @brief Define Wiegand Format.
 */
enum {
    DE_WGD_24_BIT,  ///< Wiegand protocol 24 bit standard.
    DE_WGD_26_BIT,  ///< Wiegand protocol 26 bit standard.
    DE_WGD_32_BIT,  ///< Wiegand protocol 32 bit standard.
    DE_WGD_34_BIT,  ///< Wiegand protocol 34 bit standard.
    DE_WGD_64_BIT,  ///< Wiegand protocol 64 bit standard.
    DE_WGD_66_BIT,  ///< Wiegand protocol 66 bit standard.
    DE_WGD_BIT_DEFAULT = DE_WGD_26_BIT  ///< Default Wiegand protocol is Wiegand 26 bit.
};

/**
 * @brief Define function pointer for received wiegand data. Only applies to Wiegand Input Role.
 * @param int32_t* : number of received byte.
 * @param int32_t* : number of last bits.
 * @param uint8_t* : the received data.
 * @param void* : argument of users.
 * @return NONE.
 */
typedef void (*de_wgd_recv_fn_t)(int32_t*, int32_t*, uint8_t*, void*);

/**
 * @brief Enable and initialize Wiegand channel module.
 * @param _channel is wiegand channel that defined above.
 * @param _role is role of wiegand channel. Defined above.
 * @return DE_ERR_NONE if SUCCESS. Otherwise if FAILURE.
 */
int32_t DE_WGD_init(uint8_t _channel, uint8_t _role);

/**
 * @brief Free resources and disable Wiegand Channel Module
 * @param _channel is wiegand channel that defined above.
 * @return DE_ERR_NONE if SUCCESS. Otherwise if FAILURE.
 */
int32_t DE_WGD_free(uint8_t _channel);

/**
 * @brief Send data via Wiegand Channel. Applies to Wiegand output Role only.
 * @param _channel is wiegand channel that defined above.
 * @param _data is data that sent.
 * @param _format is wiegand format that define above. Ex: DE_WGD_26_BIT.
 * @return DE_ERR_NONE if SUCCESS. Otherwise if FAILURE.
 */
int32_t DE_WGD_send(uint8_t _channel, uint8_t* _data, uint8_t _format);

/**
 * @brief Register callback function for data receiving Event. Applies to Wiegand Input Role only.
 * @param _channel is wiegand channel that defined above.
 * @param _recv_callback is callback function. This function will be call when wiegand data is received.
 * @param _arg is argument of callback function.
 * @return DE_ERR_NONE if SUCCESS. Otherwise if FAILURE.
 */
int32_t DE_WGD_reg_recv_event(uint8_t _channel, de_wgd_recv_fn_t _recv_callback, void* _arg);

/**
 * @brief Polling data from Wiegand channel. Applies to Wiegand Input Role only.
 * @param _channel is wiegand channel that defined above.
 * @param _read_number is number of received byte.
 * @param _last_bits_count is number of last bits.
 * @param _data is the received data.
 * @return DE_ERR_NONE if SUCCESS. Otherwise if FAILURE.
 */
int32_t DE_WGD_recv(uint8_t _channel, int32_t* _read_number, int32_t* _last_bits_count, uint8_t* _data);


/***************************************************************/
/*                      Duali RS232 API                        */
/***************************************************************/

/// Default baud rate RS232 Port
#define DE_RS232_DEFAULT_BAUD_RATE  115200

/**
 * @brief RS232 Port number that device support. Depending on the device, one or two ports can be supported.
 */
enum {
    DE_RS232_PORT_0, ///< RS232 Port 0
    DE_RS232_PORT_1, ///< RS232 Port 1
};

/**
 * @brief Initialize and enable RS232 Port.
 * @param _rs232 is RS232 port number that is defined above.
 * @param _baud  is baud rate. Default value is defined above. Ex: 9600, 19200, 38400, 57600, 115200.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS232_init(uint8_t _rs232, int32_t _baud);

/**
 * @brief Free resources and disable RS232 Port.
 * @param _rs232 is RS232 port number that is defined above.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS232_free(uint8_t _rs232);

/**
 * @brief Configure baud rate speed of RS232 Port
 * @param _rs232 is RS232 port number that is defined above.
 * @param _baud is baud rate. Default value is defined above. Ex: 9600, 19200, 38400, 57600, 115200.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS232_config(uint8_t _rs232, int32_t _baud);

/**
 * @brief Send data via RS232 Port that is initialized.
 * @param _rs232 is RS232 port number that is defined above.
 * @param _data is sent
 * @param _len is length of data.
 * @return Length of sent data.
 *          -1 if port is ERROR.
 */
int32_t DE_RS232_send(uint8_t _rs232, uint8_t* _data, int32_t _len);

/**
 * @brief Receive data from RS232 Port that is initialized.
 * @param _rs232 is RS232 port number that is defined above.
 * @param _buf is buffer that is received.
 * @param _max_len is maximum length that can be received.
 * @return Length of received data.
 *         0 if no data is received.
 *         -1 if the port is ERROR.
 */
int32_t DE_RS232_recv(uint8_t _rs232, uint8_t* _buf, int32_t _max_len);

/**
 * @brief Check data is available on the RS232 port.
 * @param _rs232 is RS232 port number that is defined above.
 * @return TRUE (1) if the data is available.
 *         FALSE (0) if the data is NOT available.
 */
int32_t DE_RS232_data_available(uint8_t _rs232);


/***************************************************************/
/*                      Duali RS485 API                        */
/***************************************************************/

/// Default RS485 baud rate
#define DE_RS485_DEFAULT_BAUD_RATE  115200

/**
 * @brief RS485 Port number that device support. Depending on the device, one or two ports can be supported.
 */
enum {
    DE_RS485_PORT_0, ///< RS485 Port 0
    DE_RS485_PORT_1, ///< RS485 Port 1
};

/**
 * @brief Initialize and enable RS485 Port.
 * @param _rs485 is RS485 port number that is defined above.
 * @param _baud is baud rate. Default value is defined above. Ex: 9600, 19200, 38400, 57600, 115200.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS485_init(uint8_t _rs485, int32_t _baud);

/**
 * @brief Free resources and disable RS485 Port.
 * @param _rs485 is RS485 port number that is defined above.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS485_free(uint8_t _rs485);

/**
 * @brief Configure baud rate speed of RS485 Port
 * @param _rs485 is RS485 port number that is defined above.
 * @param _baud is baud rate. Default value is defined above. Ex: 9600, 19200, 38400, 57600, 115200.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_RS485_config(uint8_t _rs485, int32_t _baud);

/**
 * @brief Send data via RS485 Port that is initialized.
 * @param _rs485 is RS485 port number that is defined above.
 * @param _data is sent
 * @param _len is length of data.
 * @return Length of sent data.
 *          -1 if port is ERROR.
 */
int32_t DE_RS485_send(uint8_t _rs485, uint8_t* _data, int32_t _len);

/**
 * @brief Receive data from RS232 Port that is initialized.
 * @param _rs485 is RS485 port number that is defined above.
 * @param _buf is buffer that is received.
 * @param _max_len is maximum length that can be received.
 * @return Length of received data.
 *         0 if no data is received.
 *         -1 if the port is ERROR.
 */
int32_t DE_RS485_recv(uint8_t _rs485, uint8_t* _buf, int32_t _max_len);

/**
 * @brief Check data is available on the RS485 port.
 * @param _rs485 is RS485 port number that is defined above.
 * @return TRUE (1) if the data is available.
 *         FALSE (0) if the data is NOT available.
 */
int32_t DE_RS485_data_available(uint8_t _rs485);
/***************************************************************/

/***************************************************************/
/*                      Duali Buzzer API                       */
/***************************************************************/

/**
 * @brief Define Tune corresponds to human audible sound.
 */
enum {
    DE_BZ_SCALE_DO = 0,     ///< Rhythm DO
    DE_BZ_SCALE_DOS,        ///< Rhythm DOS
    DE_BZ_SCALE_RE,         ///< Rhythm RE
    DE_BZ_SCALE_RES,        ///< Rhythm RES
    DE_BZ_SCALE_MI,         ///< Rhythm MI
    DE_BZ_SCALE_FA,         ///< Rhythm FA
    DE_BZ_SCALE_FAS,        ///< Rhythm FAS
    DE_BZ_SCALE_SOL,        ///< Rhythm SOL
    DE_BZ_SCALE_SOLS,       ///< Rhythm SOLS
    DE_BZ_SCALE_RA,         ///< Rhythm RA
    DE_BZ_SCALE_RAS,        ///< Rhythm RAS
    DE_BZ_SCALE_SI,         ///< Rhythm SI
    DE_BZ_SCALE_NUMBER      ///< Number of rhythms.
};

/**
 * @brief Define Buzzer octave. The BEEP sound increases with each level
 */
enum{
    DE_BZ_OCTAVE_1, ///< Octave 1
    DE_BZ_OCTAVE_2, ///< Octave 2
    DE_BZ_OCTAVE_3, ///< Octave 3
    DE_BZ_OCTAVE_4, ///< Octave 4
    DE_BZ_OCTAVE_5, ///< Octave 5
    DE_BZ_OCTAVE_6, ///< Octave 6
    DE_BZ_OCTAVE_7, ///< Octave 7
    DE_BZ_OCTAVE_8, ///< Octave 8
    DE_BZ_OCTAVE_NUMBER ///< Number of Octaves
};

/**
 * @brief Enable and initialize Buzzer module.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_BZ_init(void);

/**
 * @brief Free resource and disable Buzzer module.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_BZ_free(void);

/**
 * @brief Play tune via Buzzer.
 * @param _octave is octave.
 * @param _scale is rhythm.
 * @param _time is time that play tune. Unit: ms (mini-second).
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_BZ_play(uint8_t _octave, uint8_t _scale, int32_t _time);

/**
 * @brief Stop tune that is playing.
 * @return DE_ERR_NONE if SUCCESS, otherwise FAILURE.
 */
int32_t DE_BZ_stop(void);

#ifdef __cplusplus
}
#endif

#endif //DE_API_COMMON_H
