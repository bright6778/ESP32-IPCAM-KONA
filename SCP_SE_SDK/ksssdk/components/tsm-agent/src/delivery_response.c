/*
 * delivery_response.c
 *
 *  Created on: Apr 23, 2018
 *      Author: Autonu
 */
#include "delivery_response.h"

void parse_delivery_response_packet(char* buffer, TSM_Delivery_Response** delivery_response){

	printf("\nIn method to parse Delivery Response from byte array");

	TSM_Delivery_Response* delivery_response_parsed = (TSM_Delivery_Response* )malloc(sizeof(TSM_Delivery_Response));
	//parsing header from buffer
	parse_tsm_header(buffer,&delivery_response_parsed->header);
	int i=0;

	int actual_len_of_current_field = 0;
	int current_pos = HEADER_LENGTH;

	//parse conversation id
	char conversation_id[LEN_CONVERSATION_ID];
	for(i=0;i<LEN_CONVERSATION_ID;i++){
		if(buffer[current_pos+i]== TSM_PADDING){
			continue;
		}
		conversation_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_CONVERSATION_ID;

	delivery_response_parsed->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	delivery_response_parsed->conversation_id->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));//i holds actual length of conversation id
	memcpy(delivery_response_parsed->conversation_id->str,conversation_id,actual_len_of_current_field);
	delivery_response_parsed->conversation_id->length = actual_len_of_current_field;

	// parse result
	byte result = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->result = result;

	// parse ack use
	byte ack_use = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->ack_use = ack_use;

	// parse crc use
	byte crc_use = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->crc_use = crc_use;

	// parse crc
	char crc[LEN_CRC];
	actual_len_of_current_field = 0;
	for(i=0;i<LEN_CRC;i++){
		if(buffer[current_pos+i] == TSM_PADDING)
			continue;
		crc[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_CRC;

	delivery_response_parsed->crc = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(delivery_response_parsed->crc,crc,actual_len_of_current_field);

	// parse hb use
	byte hb_use = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->hb_use = hb_use;

	// parse reserved
	byte reserved = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->reserved = reserved;

	// parse control type
	byte control_type = buffer[current_pos];
	current_pos++;
	delivery_response_parsed->control_type = control_type;

	*delivery_response = delivery_response_parsed;

}

int get_byte_array_from_tsm_delivery_response(TSM_Delivery_Response* delivery_response, char** delivery_response_bytes){

	printf("\nIn method to get byte array from Delivery Response");

	delivery_response->header->body_length = BODY_LENGTH_DELIVERY_RESPONSE;
	char* buffer = (char*)malloc(sizeof(char)*(HEADER_LENGTH+BODY_LENGTH_DELIVERY_RESPONSE));
	char* header_bytes;
	get_byte_array_from_tsm_header(delivery_response->header,&header_bytes);
	memcpy(buffer,header_bytes,HEADER_LENGTH);
	free(header_bytes);

	int i=0;
	int current_position = HEADER_LENGTH;

	// conversation id
	memset(buffer+current_position, TSM_PADDING,LEN_CONVERSATION_ID);
	memcpy(buffer+current_position,delivery_response->conversation_id->str,delivery_response->conversation_id->length);
	current_position+=LEN_CONVERSATION_ID;

	// result
	buffer[current_position] = delivery_response->result;
	current_position++;
	// ack use
	buffer[current_position] = delivery_response->ack_use;
	current_position++;
	// crcUse
	buffer[current_position] = delivery_response->crc_use;
	current_position++;
	// crc
	buffer[current_position] = delivery_response->crc[0];
	buffer[current_position+1] = delivery_response->crc[1];
	current_position+=2;
	// hb use
	buffer[current_position] = delivery_response->hb_use;
	current_position++;
	// reserved
	buffer[current_position] = delivery_response->reserved;
	current_position++;
	// control type
	buffer[current_position] = delivery_response->control_type;

	*delivery_response_bytes = buffer;

	return HEADER_LENGTH+BODY_LENGTH_DELIVERY_RESPONSE;//total length of buffer
}
void free_tsm_delivery_response(TSM_Delivery_Response** delivery_response){

    // if(*delivery_response == NULL)
    //     return;

	free_tsm_header(&(*delivery_response)->header);
	free((*delivery_response)->conversation_id->str);
	(*delivery_response)->conversation_id->str = NULL;
	free((*delivery_response)->crc);
	(*delivery_response)->crc = NULL;
	free((*delivery_response));
	(*delivery_response) = NULL;

}

void print_tsm_delivery_response(TSM_Delivery_Response* delivery_response){

	printf("\nPrinting Delivery Response from TSM...\n");

	print_tsm_header(delivery_response->header);
	printf("\nPrinting Delivery Response Body...\n");
	printf("\nResult: %d",delivery_response->result);
	printf("\nAck Use: %d",delivery_response->ack_use);
	printf("\nCrc Use: %d",delivery_response->crc_use);
	printf("\nHb Use: %d",delivery_response->hb_use);
	printf("\nCRC: ");
	printf("%02X %02X",delivery_response->crc[0],delivery_response->crc[1]);
	int i=0;
	printf("\nConversation ID: ");
	for(i=0;i<delivery_response->conversation_id->length;i++)
		printf("%c",delivery_response->conversation_id->str[i]);
}

