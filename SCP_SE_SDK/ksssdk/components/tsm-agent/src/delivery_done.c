/*
 * apdu_response.c
 *
 *  Created on: Apr 23, 2018
 *      Author: Autonu
 */

#include "delivery_done.h"

#define LEN_RESULT				 1

#define BODY_LENGTH_DELIVERY_DONE   (LEN_CONVERSATION_ID + LEN_RESULT)

void parse_tsm_delivery_done(char* buffer, TSM_Delivery_Done** delivery_done){

	TSM_Delivery_Done* delivery_done_parsed = (TSM_Delivery_Done* )malloc(sizeof(TSM_Delivery_Done));
	//parsing header from buffer
	parse_tsm_header(buffer,&delivery_done_parsed->header);
	int i=0;
	int actual_len_of_current_field = 0;
	int current_pos = HEADER_LENGTH;

	//parse conversation id
	char conversation_id[LEN_CONVERSATION_ID];
	for(i=0;i<LEN_CONVERSATION_ID;i++){
		if(buffer[current_pos+i] == TSM_PADDING){
			continue;
		}
		conversation_id[actual_len_of_current_field] = buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos += LEN_CONVERSATION_ID;

	delivery_done_parsed->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	delivery_done_parsed->conversation_id->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(delivery_done_parsed->conversation_id->str, conversation_id, actual_len_of_current_field);
	delivery_done_parsed->conversation_id->length = actual_len_of_current_field;

	delivery_done_parsed->result = buffer[current_pos];

	*delivery_done = delivery_done_parsed;
}

int get_byte_array_from_delivery_done(TSM_Delivery_Done* delivery_done, char** tsm_delivery_done_bytes){

	int buffer_len = HEADER_LENGTH + BODY_LENGTH_DELIVERY_DONE;
	char* buffer = (char*)malloc(sizeof(char)*buffer_len);
	char* header_bytes;

	delivery_done->header->body_length = BODY_LENGTH_DELIVERY_DONE;
	get_byte_array_from_tsm_header(delivery_done->header, &header_bytes);

	memcpy(buffer, header_bytes, HEADER_LENGTH);
	free(header_bytes);

	int current_position = HEADER_LENGTH;

	// conversation id
	memset(buffer+current_position, TSM_PADDING, LEN_CONVERSATION_ID);
	memcpy(buffer+current_position,delivery_done->conversation_id->str,delivery_done->conversation_id->length);
	current_position += LEN_CONVERSATION_ID;

	buffer[current_position] = delivery_done->result;

	*tsm_delivery_done_bytes = buffer;

	return buffer_len;
}

void free_delivery_done(TSM_Delivery_Done** delivery_done){

    // if(*delivery_done == NULL)
    //     return;
	free_tsm_header(&(*delivery_done)->header);
	free((*delivery_done)->conversation_id->str);
	free((*delivery_done)->conversation_id);
	(*delivery_done)->conversation_id = NULL;
	free((*delivery_done));
	*delivery_done = NULL;
}

