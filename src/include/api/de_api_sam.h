/**
 * @file de_api_sam.h
 * @author thuan@duali.com
 * @date 28/11/2022.
 * @brief This is SAM APIs that is supported by Duali Electronic.
 */

#ifndef DE_API_SAM_H
#define DE_API_SAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "de_types.h"

/**
 * @brief Enable and Initialize SAM Module.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_init();

/**
 * @brief Free resource and disable SAM Module.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_free();

/**
 * @brief Turn on SAM Module.
 * @return DE_ERR_NONE if SUCCESS.
 * @param slotno : sam slot number to power on. Must be 0.
 * @param ispower5v : poweron voltage. VCC 5V is 1,VCC 3V is 0.
 * @param atr_len : atr length received from card.
 * @param atr_data : : atr data received from card.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_on(int32_t slotno,int32_t ispower5v, int32_t *atr_len, uint8_t* atr_data);

/**
 * @brief Turn off SAM Module.
 * @param slotno : sam slot number to power off. Must be 0.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_off(int32_t slotno);


/**
 * @brief Polling data in the SAM field.
 * @param _data_len : length of data.
 * @param data : data that is sent.
 * @param _out_len : returned length.
 * @param _response : response that is returned.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_polling(int32_t _data_len, uint8_t* data, int32_t* _out_len, uint8_t* _response);

/**
 * @brief This function transfers APDU command to sam card.
 * @param slotno : sam slot number to tranceive. Must be 0.
 * @param _data_len : length of data.
 * @param _data : data that is sent.
 * @param _out_len : returned length.
 * @param _response : response that is returned.
 * @return DE_ERR_NONE if SUCCESS.
 *         @n Otherwise FAILURE. Please check in the de_err.h file.
 */
int32_t DE_SAM_apdu(int32_t slotno, int32_t _data_len, uint8_t* _data, int32_t* _out_len, uint8_t* _response);


#ifdef __cplusplus
}
#endif

#endif //DE_API_SAM_H
