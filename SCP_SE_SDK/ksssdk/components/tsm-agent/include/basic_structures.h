/*
 * basic_structures.h
 *
 *  Created on: May 10, 2018
 *      Author: GM Al Mamun
 */

#ifndef TSM_SDK_BASIC_STRUCTURES_H_
#define TSM_SDK_BASIC_STRUCTURES_H_

typedef unsigned char byte;

typedef struct _CUSTOM_STRING{
	byte* str;
	int length;
}CUSTOM_STRING;

#define TSM_PADDING 0X20

#endif /* TSM_SDK_BASIC_STRUCTURES_H_ */
