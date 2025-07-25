/*
 * apdu.h
 *
 *  Created on: May 10, 2018
 *      Author: Swasti
 */

#ifndef TSM_SDK_INCLUDE_APDU_H_
#define TSM_SDK_INCLUDE_APDU_H_
#include <cJSON.h>
#define LEN_AID					 32
#define LEN_TOTAL_APDU_COUNT	 2
#define LEN_APDU_LENGTH			 2

#define BODY_LENGTH_COMMAND  	LEN_CONVERSATION_ID + LEN_AID + LEN_TOTAL_APDU_COUNT + LEN_APDU_LENGTH
#define BODY_LENGTH_RESPONSE  	LEN_CONVERSATION_ID + LEN_AID + LEN_TOTAL_APDU_COUNT

typedef struct _TSM_APDU
{
	cJSON_bool 			is_command;
	u_int16_t 			total_apdu_count;

	CUSTOM_STRING 		*conversation_id;
	CUSTOM_STRING 		*aid;
	CUSTOM_STRING 		**apdus;
	CUSTOM_STRING 		**rpdus;

	TSM_Packet_Header 	*header;
}TSM_APDU;

void parse_tsm_apdu(char* buffer, TSM_APDU** apdu);
void print_tsm_apdu(TSM_APDU* tsm_apdu);
void free_apdu(TSM_APDU** tsm_apdu);
int get_byte_array_from_apdu(TSM_APDU* apdu, char** tsm_apdu_bytes,cJSON_bool is_command);

#endif /* TSM_SDK_INCLUDE_APDU_H_ */
