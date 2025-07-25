/*
 * delivery_response.h
 *
 *  Created on: May 10, 2018
 *      Author: Swasti
 */
#include "tsm_header.h"

#ifndef TSM_SDK_INCLUDE_DELIVERY_RESPONSE_H_
#define TSM_SDK_INCLUDE_DELIVERY_RESPONSE_H_


#define LEN_RESULT				 1
#define LEN_ACK_USE				 1
#define LEN_CRC_USE				 1
#define LEN_CRC					 2
#define LEN_HB_USE				 1
#define LEN_RESERVED			 1
#define LEN_CONTROLTYPE			 1

#define BODY_LENGTH_DELIVERY_RESPONSE 			LEN_CONVERSATION_ID +LEN_RESULT +LEN_ACK_USE +LEN_CRC_USE +LEN_CRC +LEN_HB_USE +LEN_RESERVED +LEN_CONTROLTYPE

typedef struct _TSM_Delivery_Response{

	CUSTOM_STRING* conversation_id;

	byte result;
	byte ack_use;
	byte crc_use;
	byte* crc;
	byte hb_use;
	byte reserved;
	byte control_type;

	TSM_Packet_Header* header;
}TSM_Delivery_Response;

void parse_delivery_response_packet(char* buffer, TSM_Delivery_Response** delivery_response);
int get_byte_array_from_tsm_delivery_response(TSM_Delivery_Response* delivery_response, char** delivery_response_bytes);
void print_tsm_delivery_response(TSM_Delivery_Response* delivery_response);
void free_tsm_delivery_response(TSM_Delivery_Response** delivery_response);
#endif /* TSM_SDK_INCLUDE_DELIVERY_RESPONSE_H_ */
