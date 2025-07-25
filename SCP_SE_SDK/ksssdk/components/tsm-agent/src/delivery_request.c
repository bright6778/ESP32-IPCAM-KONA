#include "tsm_header.h"
#include "delivery_request.h"

void parse_delivery_request_packet(char* buffer, TSM_Delivery_Request** delivery_request){

	printf("\nIn method to parse Delivery Request");
	TSM_Delivery_Request* delivery_request_parsed = (TSM_Delivery_Request* )malloc(sizeof(TSM_Delivery_Request));
	//parsing header from buffer
	parse_tsm_header(buffer,&delivery_request_parsed->header);
	int i=0;
	int current_pos = HEADER_LENGTH;

	//conversationId
	char conversation_id[LEN_CONVERSATION_ID];
	int actual_len_of_current_field = 0;
	for(i=0;i<LEN_CONVERSATION_ID;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			continue;
		}
		conversation_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos += LEN_CONVERSATION_ID;

	delivery_request_parsed->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	delivery_request_parsed->conversation_id->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(delivery_request_parsed->conversation_id->str,conversation_id,actual_len_of_current_field);
	delivery_request_parsed->conversation_id->length = actual_len_of_current_field;

	//delivery idx
	u_int16_t delivery_id = (buffer[current_pos]<<8)|buffer[current_pos+1];
	delivery_request_parsed->delivery_idx = delivery_id;
	current_pos+=2;

	//opcode
	char op_code = buffer[current_pos];
	current_pos++;

	//seid
	char se_id[LEN_SEID];
	actual_len_of_current_field = 0;

	for(i=0;i<LEN_SEID;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			continue;
		}
		se_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_SEID;

	delivery_request_parsed->seid = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	delivery_request_parsed->seid->length = actual_len_of_current_field;
	delivery_request_parsed->seid->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field));
	memcpy(delivery_request_parsed->seid->str,se_id,actual_len_of_current_field);

	//sir
	char sir_id[LEN_SIR];
	actual_len_of_current_field = 0;
	for(i=0;i<LEN_SIR;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			continue;
		}
		sir_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_SIR;
	if(actual_len_of_current_field!=0){
		delivery_request_parsed->sir =(CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
		delivery_request_parsed->sir->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field+1));
		memcpy(delivery_request_parsed->sir->str,sir_id,actual_len_of_current_field);
		delivery_request_parsed->sir->length = actual_len_of_current_field;
	}

	//appid
	char app_id[LEN_APPID];
	actual_len_of_current_field = 0;

	for(i=0;i<LEN_APPID;i++){
		if(buffer[current_pos+i]==TSM_PADDING){
			continue;
		}
		app_id[actual_len_of_current_field]=buffer[current_pos+i];
		actual_len_of_current_field++;
	}

	current_pos+=LEN_APPID;

	delivery_request_parsed->app_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	delivery_request_parsed->app_id->str = (byte*)malloc(sizeof(byte)*(actual_len_of_current_field+1));
	memcpy(delivery_request_parsed->app_id->str,app_id,actual_len_of_current_field);
	delivery_request_parsed->app_id->length = actual_len_of_current_field;

	*delivery_request = delivery_request_parsed;

}

int get_byte_array_from_tsm_delivery_request(TSM_Delivery_Request* delivery_request, char** delivery_request_bytes){

	printf("\nIn method to get byte array from Delivery Request");
    print_delivery_request(delivery_request);
	int total_buff_len = HEADER_LENGTH+BODY_LENGTH_DELIVERY_REQUEST;
	char* buffer = (char*)malloc(sizeof(char)*(total_buff_len));

	//header
	char* header_bytes;
	delivery_request->header->body_length = BODY_LENGTH_DELIVERY_REQUEST;
	int header_len = get_byte_array_from_tsm_header(delivery_request->header,&header_bytes);
	memcpy(buffer,header_bytes,header_len);
	free(header_bytes);
	int current_position = HEADER_LENGTH;

	// conversation id
	memset(buffer+current_position, TSM_PADDING,LEN_CONVERSATION_ID);
	memcpy(buffer+current_position,delivery_request->conversation_id->str,delivery_request->conversation_id->length);
	current_position+=LEN_CONVERSATION_ID;

	// delivery index
	buffer[current_position] = (delivery_request->delivery_idx&0xFF00)>>8;
	buffer[current_position+1] = delivery_request->delivery_idx&0x00FF;
	current_position+=2;

	// op code
	buffer[current_position] = 0x00;
	current_position++;

	// seid
	memset(buffer+current_position, TSM_PADDING,LEN_SEID);
	memcpy(buffer+current_position,delivery_request->seid->str,delivery_request->seid->length);
	current_position+=LEN_SEID;


	// sir
	memset(buffer+current_position, TSM_PADDING,LEN_SIR);
	memcpy(buffer+current_position,delivery_request->sir->str,delivery_request->sir->length);
	current_position+=LEN_SIR;

	//appid
	memset(buffer+current_position, TSM_PADDING,LEN_APPID);
	memcpy(buffer+current_position,delivery_request->app_id->str,delivery_request->app_id->length);
	current_position+=LEN_APPID;

	*delivery_request_bytes = buffer;

	return total_buff_len;
}
void free_delivery_request(TSM_Delivery_Request** delivery_request){

    // if(*delivery_request == NULL)
    //     return;

	free_tsm_header(&(*delivery_request)->header);
	free((*delivery_request)->conversation_id->str);
	(*delivery_request)->conversation_id->str = NULL;
	free((*delivery_request)->conversation_id);
	(*delivery_request)->conversation_id = NULL;

	free((*delivery_request)->sir->str);
	(*delivery_request)->sir->str = NULL;
	free((*delivery_request)->sir);
	(*delivery_request)->sir = NULL;

	free((*delivery_request)->seid->str);
	(*delivery_request)->seid->str = NULL;
	free((*delivery_request)->seid);
	(*delivery_request)->seid = NULL;

	free((*delivery_request)->app_id->str);
	(*delivery_request)->app_id->str = NULL;
	free((*delivery_request)->app_id);
	(*delivery_request)->app_id = NULL;

	free((*delivery_request));
	(*delivery_request) = NULL;

}

void print_delivery_request(TSM_Delivery_Request* delivery_request){

	print_tsm_header(delivery_request->header);

	printf("\nPrinting Delivery Request Body...\n");
	int i=0;
	printf("\nConversation ID: ");
	for(i=0;i<delivery_request->conversation_id->length;i++)
		printf("%c",delivery_request->conversation_id->str[i]);
	//	printf("\nConversation ID: %s",delivery_request->conversation_id->str);
	printf("\nDelivery Index: %d",delivery_request->delivery_idx);

	printf("\nSE ID: ");
	for(i=0;i<delivery_request->seid->length;i++)
		printf("%c",delivery_request->seid->str[i]);
	printf("\nSIR: ");
	for(i=0;i<delivery_request->sir->length;i++)
		printf("%c",delivery_request->sir->str[i]);
	printf("\nApp ID: ");
	for(i=0;i<delivery_request->app_id->length;i++)
		printf("%c",delivery_request->app_id->str[i]);



}
