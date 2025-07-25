#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "basic_structures.h"

#ifndef REQUEST_STRUCTS_
#define REQUEST_STRUCTS_

#define LEN_MSG_ID 36

#define CURRENT_VERSION 1

/** The Constant LEN_VERSION. */
#define LEN_VERSION 1

/** The Constant LEN_DIRECTION. */
#define LEN_DIRECTION 1

/** The Constant LEN_MSG_TYPE. */
#define LEN_MSG_TYPE 1

/** The Constant LEN_TOTAL_COUNT. */
#define LEN_TOTAL_COUNT 2

/** The Constant LEN_CURRENT_COUNT. */
#define LEN_CURRENT_COUNT 2

/** The Constant LEN_RESERVED1. */
#define LEN_KIC 1

/** The Constant LEN_RESERVED2. */
#define LEN_KID 1

/** The Constant LEN_RESERVED3. */
#define LEN_ENCYN 1

#define LEN_HOST_ID 12

#define LEN_CONVERSATION_ID 60

/** The Constant LEN_BODY_LENGTH. */
#define LEN_BODY_LENGTH 2

/** The Constant LENGTH. */
#define HEADER_LENGTH  LEN_VERSION + LEN_DIRECTION + LEN_MSG_TYPE+ LEN_TOTAL_COUNT + LEN_CURRENT_COUNT + LEN_KIC+ LEN_KID + LEN_ENCYN + LEN_HOST_ID + LEN_CONVERSATION_ID + LEN_BODY_LENGTH



typedef enum _MESSAGE_TYPE{
	UNKNOWN_MESSAGE_TYPE = 0,
	DELIVERY_REQUEST =1,
	DELIVERY_RESPONSE	,
	DELIVERY_DONE		,
	DELIVERY_DONE_ACK	,
	APDU_COMMAND		,
	APDU_RESPONSE		,
	HEARTBIT
}MESSAGE_TYPE;

typedef enum _DIRECTION{
	UNKNOWN_DIRECTION		= 0x00,
	TO_TSM					= 0x0F,
	FROM_TSM  				= 0xF0
}DIRECTION;

typedef struct _TSM_Packet_Header{

	/** The version. */
	int version;

	/**
	 * TSM server to Client or Client to TSM server
	 *
	 */
	DIRECTION direction;

	/** The msg type. */
	MESSAGE_TYPE msg_type;

	/** The total count. */
	u_int16_t total_count;

	/** The current count. */
	u_int16_t current_count;

	/** The reserved1. */
	//byte k_ic = 0x00;
	byte k_ic;

	/** The reserved2. */
	//byte k_id = 0x00;
	byte k_id;

	/** The reserved3. */
	//byte enc_yn = 0x00;
	byte enc_yn;

	CUSTOM_STRING* host_id;

	CUSTOM_STRING* conversation_id;

	/** The body length. */
	u_int16_t body_length;
}TSM_Packet_Header;

DIRECTION get_direction(byte direction);

MESSAGE_TYPE get_msg_type(byte msg_type);

void parse_tsm_header(char* buffer,TSM_Packet_Header** packet_header);

int get_byte_array_from_tsm_header(TSM_Packet_Header* packet_header,char** header_bytes);

void print_tsm_header(TSM_Packet_Header* packet_header);

void free_tsm_header(TSM_Packet_Header** packet_header);
#endif
