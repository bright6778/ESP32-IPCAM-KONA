/*
 * apdu_command.c
 *
 *  Created on: Apr 23, 2018
 *      Author: Autonu
 */
#include "tsm_header.h"
// #include "cJSON/cJSON.h"
#include "apdu.h"
#include <stdbool.h>
#include "tsm_debug.h"

/**
 *
 */
void parse_tsm_apdu(char* buffer, TSM_APDU** apdu)
{
	//TSM_SDK_DEBUG_MSG(3, "In method for parsing apdu");

	TSM_APDU* apdu_parsed = (TSM_APDU* )malloc(sizeof(TSM_APDU));
	if(apdu_parsed == NULL){
		//TSM_SDK_DEBUG_MSG(3, "Memory Allocation Failed");
	}
	//parsing header from buffer
	parse_tsm_header(buffer,&apdu_parsed->header);
	int i=0;
	int actual_len_of_current_field = 0;
	int current_pos = HEADER_LENGTH;

	//parse conversation id
	char conversation_id[LEN_CONVERSATION_ID];
	for(i=0;i<LEN_CONVERSATION_ID;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			continue;
		}
		conversation_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_CONVERSATION_ID;

	apdu_parsed->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	apdu_parsed->conversation_id->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(apdu_parsed->conversation_id->str,conversation_id,actual_len_of_current_field);
	apdu_parsed->conversation_id->length = actual_len_of_current_field;

	// parse aid
	char aid[LEN_AID];
	actual_len_of_current_field = 0;

	for(i=0;i<LEN_AID;i++){
		if(buffer[current_pos+i]== TSM_PADDING ){
			continue;
		}

		aid[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}
	printf("\n");

	current_pos+=LEN_AID;
	apdu_parsed->aid = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	apdu_parsed->aid->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(apdu_parsed->aid->str,aid,actual_len_of_current_field);
	apdu_parsed->aid->length = actual_len_of_current_field;

	// parse total apdu count
	u_int16_t total_apdu_count = (buffer[current_pos]<<8) | buffer[current_pos+1];
	current_pos += 2;
	apdu_parsed->total_apdu_count = total_apdu_count;
	apdu_parsed->is_command = true;
	apdu_parsed->apdus = (CUSTOM_STRING**)malloc(sizeof(CUSTOM_STRING*)*total_apdu_count);
	// parse APDUs
	for(i=0; i<total_apdu_count; i++)
	{
		int  apdu_length = -1;
		apdu_length = (buffer[current_pos]<<8)|buffer[current_pos+1];
		current_pos+=2;
		if(apdu_length<0) {
			printf("\n%s\n","Wrong array Length");
			continue;//what should be done??
		}

		apdu_parsed->apdus[i] = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
		apdu_parsed->apdus[i]->str = (byte*)malloc(sizeof(byte)*(apdu_length));
		apdu_parsed->apdus[i]->length = apdu_length;


		int j=0;
		for(j=0;j<apdu_length;j++){
			apdu_parsed->apdus[i]->str[j] = buffer[current_pos+j];
		}
		current_pos+=apdu_length;
	}

	*apdu = apdu_parsed;
}

int get_byte_array_from_apdu_command(TSM_APDU* apdu, char** tsm_apdu_bytes){

	printf("\nIn method to get byte array from APDU Command..\n");
	int total_apdu_bytes_length=0;
	int i=0;
	for(i=0;i<apdu->total_apdu_count;i++){
		total_apdu_bytes_length+=apdu->apdus[i]->length;
	}

	int buffer_len = HEADER_LENGTH + BODY_LENGTH_COMMAND + total_apdu_bytes_length;
	char* buffer = (char*)malloc(sizeof(char)*buffer_len);
	char* header_bytes;
	apdu->header->body_length = BODY_LENGTH_COMMAND + (u_int16_t)total_apdu_bytes_length;
	get_byte_array_from_tsm_header(apdu->header,&header_bytes);

	memcpy(buffer,header_bytes,HEADER_LENGTH);
	free(header_bytes);

	int current_position=HEADER_LENGTH;

	// conversation id
	memset(buffer+current_position, TSM_PADDING,LEN_CONVERSATION_ID);
	memcpy(buffer+current_position,apdu->conversation_id->str,apdu->conversation_id->length);
	current_position+=LEN_CONVERSATION_ID;

	// aid
	memset(buffer+current_position, TSM_PADDING,LEN_AID);
	memcpy(buffer+current_position,apdu->aid->str,apdu->aid->length);
	current_position+=LEN_AID;

	// total apdu count
	buffer[current_position] = (apdu->total_apdu_count&0xFF00)>>8;
	buffer[current_position+1] = apdu->total_apdu_count&0x00FF;
	current_position+=2;

    //apdus
	for(i=0;i<apdu->total_apdu_count;i++){

        buffer[current_position] = (apdu->rpdus[i]->length&0xFF00)>>8;
		buffer[current_position+1] = apdu->rpdus[i]->length&0x00FF;
		current_position+=2;

		memcpy(buffer + current_position,apdu->apdus[i]->str,apdu->apdus[i]->length);

		current_position+=apdu->apdus[i]->length;
	}

	*tsm_apdu_bytes = buffer;

	return buffer_len;

}

int get_byte_array_from_apdu_response(TSM_APDU* apdu, char** tsm_apdu_bytes){

	printf("\nIn method to get byte array from APDU Response..\n");

	int total_apdu_bytes_length=0;
	int i=0;
	for(i=0;i<apdu->total_apdu_count;i++){
		total_apdu_bytes_length+= LEN_APDU_LENGTH+apdu->rpdus[i]->length;
	}

	int buffer_len = HEADER_LENGTH + BODY_LENGTH_RESPONSE + total_apdu_bytes_length;
	char* buffer = (char*)malloc(sizeof(char)*buffer_len);
	char* header_bytes;

	apdu->header->body_length = BODY_LENGTH_RESPONSE + (u_int16_t)total_apdu_bytes_length;
	get_byte_array_from_tsm_header(apdu->header,&header_bytes);

	memcpy(buffer,header_bytes,HEADER_LENGTH);
	free(header_bytes);

	int current_position=HEADER_LENGTH;

	// conversation id
	memset(buffer+current_position, TSM_PADDING,LEN_CONVERSATION_ID);
	memcpy(buffer+current_position,apdu->conversation_id->str,apdu->conversation_id->length);
	current_position+=LEN_CONVERSATION_ID;

	// aid
	memset(buffer+current_position, TSM_PADDING,LEN_AID);
	memcpy(buffer+current_position,apdu->aid->str,apdu->aid->length);
	current_position+=LEN_AID;

	// total apdu count
	buffer[current_position] = (apdu->total_apdu_count&0xFF00)>>8;
	buffer[current_position+1] = apdu->total_apdu_count&0x00FF;
	current_position+=2;

	for(i=0;i<apdu->total_apdu_count;i++){

		buffer[current_position] = (apdu->rpdus[i]->length&0xFF00)>>8;
		buffer[current_position+1] = apdu->rpdus[i]->length&0x00FF;
		current_position+=2;

		memcpy(buffer+current_position,apdu->rpdus[i]->str,apdu->rpdus[i]->length);
		current_position+=apdu->rpdus[i]->length;
	}

	*tsm_apdu_bytes = buffer;

	return buffer_len;
}

int get_byte_array_from_apdu(TSM_APDU* apdu, char** tsm_apdu_bytes,cJSON_bool is_command){

	if(is_command == 0){
		return get_byte_array_from_apdu_response(apdu,tsm_apdu_bytes);

	}else
		return get_byte_array_from_apdu_command(apdu,tsm_apdu_bytes);
}

void free_apdu(TSM_APDU** tsm_apdu){

    // if(*tsm_apdu == NULL)
    //     return;

	free_tsm_header(&(*tsm_apdu)->header);

	free((*tsm_apdu)->aid->str);
	(*tsm_apdu)->aid->str = NULL;
	free((*tsm_apdu)->aid);
	(*tsm_apdu)->aid = NULL;
	free((*tsm_apdu)->conversation_id->str);
	(*tsm_apdu)->conversation_id->str = NULL;
	free((*tsm_apdu)->conversation_id);
	(*tsm_apdu)->conversation_id = NULL;

	int i=0;
	for(i=0;i<(*tsm_apdu)->total_apdu_count;i++){
		free((*tsm_apdu)->apdus[i]->str);
		free((*tsm_apdu)->rpdus[i]->str);
		(*tsm_apdu)->apdus[i]->str = NULL;
		(*tsm_apdu)->rpdus[i]->str = NULL;
	}

	free((*tsm_apdu)->apdus);
	free((*tsm_apdu)->rpdus);
	(*tsm_apdu)->apdus = NULL;
	(*tsm_apdu)->rpdus = NULL;

	(*tsm_apdu) = NULL;
	//TSM_SDK_DEBUG_MSG(3, "In method for FREEING apdu");
}

void print_tsm_apdu(TSM_APDU* tsm_apdu){

	printf("\nPrinting TSM APDU...\n");
	print_tsm_header(tsm_apdu->header);
	int i=0;
	printf("\nPrinting TSM APDU body\n");
	printf("\nConversation Id: ");
	for(i=0;i<tsm_apdu->conversation_id->length;i++)
		printf("%c",tsm_apdu->conversation_id->str[i]);

	printf("\nAID: ");
	for(i=0;i<tsm_apdu->aid->length;i++)
		printf("%02X",tsm_apdu->aid->str[i]);

	printf("\nTotal Apdu Count: %d",tsm_apdu->total_apdu_count);

	if(tsm_apdu->is_command){
		printf("\nAPDU Command\n");
		for(i=0;i<tsm_apdu->total_apdu_count && tsm_apdu->apdus!=NULL;i++){
			int j=0;
			CUSTOM_STRING* cur_apdu = tsm_apdu->apdus[i];
			printf("\nAPDU(in hex)[%d] with len %d: ",i,cur_apdu->length);
			for(j=0;j<cur_apdu->length;j++){
				printf("%02X",cur_apdu->str[j]);
			}
			printf("\n");
		}
	}else{
		printf("\nAPDU Response\n");
		for(i=0;i<tsm_apdu->total_apdu_count && tsm_apdu->rpdus!=NULL;i++){
			int j=0;
			CUSTOM_STRING* cur_apdu = tsm_apdu->rpdus[i];
			printf("\nRPDU(in hex)[%d]: ",i);
			for(j=0;j<cur_apdu->length;j++){
				printf("%02X",cur_apdu->str[j]);
			}
			printf("\n");
		}
	}

}
