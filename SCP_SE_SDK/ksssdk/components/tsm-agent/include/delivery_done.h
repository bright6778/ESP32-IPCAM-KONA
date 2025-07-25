/*
 * delivery_done.h
 *
 *  Created on: May 10, 2018
 *      Author: Swasti
 */
#include "tsm_header.h"

#ifndef TSM_SDK_INCLUDE_DELIVERY_DONE_H_
#define TSM_SDK_INCLUDE_DELIVERY_DONE_H_

typedef struct _TSM_Delivery_Done{

	CUSTOM_STRING* conversation_id;
	byte result;
	TSM_Packet_Header* header;
}TSM_Delivery_Done;

void parse_tsm_delivery_done(char* buffer, TSM_Delivery_Done** delivery_done);
int get_byte_array_from_delivery_done(TSM_Delivery_Done* delivery_done, char** tsm_delivery_done_bytes);
void free_delivery_done(TSM_Delivery_Done** delivery_done);
#endif /* TSM_SDK_INCLUDE_DELIVERY_DONE_H_ */
