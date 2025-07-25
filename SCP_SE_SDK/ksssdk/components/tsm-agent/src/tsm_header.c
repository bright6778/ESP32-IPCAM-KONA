/*
 * tsm_header.c
 *
 *  Created on: Apr 23, 2018
 *      Author: Autonu
 */

#include "tsm_header.h"
#include <string.h>
#include <stdio.h>

DIRECTION get_direction(byte direction){
	if(direction == 0x0F)
		return TO_TSM;
	else if(direction == 0xF0)
		return FROM_TSM;
	else
		return UNKNOWN_DIRECTION;
}

MESSAGE_TYPE get_msg_type(byte msg_type){

	switch (msg_type) {
	case 1:
		return DELIVERY_REQUEST;
		break;
	case 2:
		return DELIVERY_RESPONSE;
		break;
	case 3:
		return DELIVERY_DONE;
		break;
	case 4:
		return DELIVERY_DONE_ACK;
		break;
	case 5:
		return APDU_COMMAND;
		break;
	case 6:
		return APDU_RESPONSE;
		break;
	case 7:
		return HEARTBIT;
		break;
	default:
		return UNKNOWN_MESSAGE_TYPE;
		break;
	}
}

/**
 *
 */
void parse_tsm_header(char* buffer, TSM_Packet_Header** packet_header){

	int current_pos = 0;
	byte version = buffer[current_pos]&(0x0F);
	current_pos++;
	byte direction = buffer[current_pos];
	current_pos++;
	byte msg_type = buffer[current_pos];
	current_pos++;
	u_int16_t total_count = (buffer[current_pos]<<8)|buffer[current_pos+1];
	current_pos+=2;
	u_int16_t current_count = (buffer[current_pos]<<8)|buffer[current_pos+1];
	current_pos+=2;
	byte k_ic = buffer[current_pos];
	current_pos++;
	byte k_id = buffer[current_pos];
	current_pos++;
	byte enc_yn = buffer[current_pos];
	current_pos++;

	char host_id[LEN_HOST_ID];
	int i=0;
	int host_id_len=0;

	int actual_len_of_current_field=0;

	for(;i<LEN_HOST_ID;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			if((i==LEN_HOST_ID-1)||(buffer[current_pos+i+1]== TSM_PADDING))
				continue;
		}
		host_id[actual_len_of_current_field] = buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	host_id_len = actual_len_of_current_field;
	current_pos +=LEN_HOST_ID;

	char conversation_id[LEN_CONVERSATION_ID];
	int conversation_id_len = 0;
	actual_len_of_current_field=0;
	for(i=0;i<LEN_CONVERSATION_ID;i++){
		if(buffer[current_pos+i]== TSM_PADDING){
			continue;
		}
		conversation_id[actual_len_of_current_field] = buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	conversation_id_len = actual_len_of_current_field;

	current_pos +=LEN_CONVERSATION_ID;

	u_int16_t body_len = (buffer[current_pos]<<8)|buffer[current_pos+1];

	TSM_Packet_Header* packet_header_parsed = (TSM_Packet_Header*)malloc(sizeof(TSM_Packet_Header));

	packet_header_parsed->version = version;
	packet_header_parsed->direction = get_direction(direction);
	packet_header_parsed->msg_type = get_msg_type(msg_type);
	packet_header_parsed->total_count = total_count;
	packet_header_parsed->current_count = current_count;
	packet_header_parsed->k_ic = k_ic;
	packet_header_parsed->k_id = k_id;
	packet_header_parsed->enc_yn = enc_yn;
	packet_header_parsed->host_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	packet_header_parsed->host_id->str = (byte*)malloc(sizeof(byte)*(host_id_len));
	memcpy(packet_header_parsed->host_id->str,host_id,host_id_len);
	packet_header_parsed->host_id->length = host_id_len;
	packet_header_parsed->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	packet_header_parsed->conversation_id->str = (byte*)malloc(sizeof(byte)*(conversation_id_len));
	memcpy(packet_header_parsed->conversation_id->str,conversation_id,conversation_id_len);
	packet_header_parsed->conversation_id->length = conversation_id_len;
	packet_header_parsed->body_length = body_len;

	*packet_header = packet_header_parsed;
}

int get_byte_array_from_tsm_header(TSM_Packet_Header* packet_header,char** header_bytes){

	printf("\nIn method to get byte array from tsm Header\n");
	char* buffer = (char*)malloc(sizeof(char)*(HEADER_LENGTH+1));
	int current_buffer_position=0;

	byte version = (packet_header->version&0x00FF);
	buffer[current_buffer_position] = version;
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->direction);
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->msg_type);
	current_buffer_position++;
	//total byte count
	buffer[current_buffer_position] = (packet_header->total_count&0xFF00)>>8;
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->total_count&0x00FF);
	current_buffer_position++;
	//current count
	buffer[current_buffer_position] = (packet_header->current_count&0xFF00)>>8;
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->current_count&0x00FF);
	current_buffer_position++;

	buffer[current_buffer_position] = (packet_header->k_ic);
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->k_id);
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->enc_yn);
	current_buffer_position++;

	//host id
	memset(buffer+current_buffer_position,TSM_PADDING,LEN_HOST_ID);
	current_buffer_position += 7;
	memcpy(buffer+current_buffer_position,packet_header->host_id->str,packet_header->host_id->length);
	current_buffer_position+=LEN_HOST_ID-7;

    //Conversation id
	memset(buffer+current_buffer_position,TSM_PADDING,LEN_CONVERSATION_ID);
	current_buffer_position += 6;
	memcpy(buffer+current_buffer_position,packet_header->conversation_id->str,packet_header->conversation_id->length);
	current_buffer_position+=LEN_CONVERSATION_ID-6;

	buffer[current_buffer_position] = (packet_header->body_length&0xFF00)>>8;
	current_buffer_position++;
	buffer[current_buffer_position] = (packet_header->body_length&0x00FF);
	current_buffer_position++;

	*header_bytes = buffer;

	return current_buffer_position;

}
void free_tsm_header(TSM_Packet_Header** packet_header){
    if(*packet_header == NULL)
        return;
    free((*packet_header)->host_id->str);
    (*packet_header)->host_id->str = NULL;
    free((*packet_header)->host_id);
    (*packet_header)->host_id = NULL;
    free((*packet_header)->conversation_id->str);
    (*packet_header)->conversation_id->str = NULL;
    free((*packet_header)->conversation_id);
    (*packet_header)->conversation_id = NULL;
    free((*packet_header));
    (*packet_header) = NULL;
}

void print_tsm_header(TSM_Packet_Header* packet_header){

	int i=0;
	printf("\nPrinting TSM Header..\n");

	printf("\nVersion: %d\n",packet_header->version);
	printf("\nDirection: %02X\n",packet_header->direction);
	printf("\nMsg_type: %d\n",packet_header->msg_type);
	printf("\nTotal_count: %d\n",packet_header->total_count);
	printf("\nCurrent_count: %d\n",packet_header->current_count);
	printf("\nBody_length: %d\n",packet_header->body_length);
	printf("\nK_ic: %d\n",packet_header->k_ic);
	printf("\nK_id: %d\n",packet_header->k_id);
	printf("\nEnc_yn: %d\n",packet_header->enc_yn);

	printf("\nConversation ID: ");
		for(i=0;i<packet_header->conversation_id->length;i++){
			printf("%c",packet_header->conversation_id->str[i]);
		}
	printf("\nHost ID: ");
	for(i=0;i<packet_header->host_id->length;i++){
		printf("%c",packet_header->host_id->str[i]);
	}

}
