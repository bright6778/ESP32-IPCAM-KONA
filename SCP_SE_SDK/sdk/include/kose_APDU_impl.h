#include "kose_tlv.h"
#include "kose_enums.h"
#include "kona_kss_api.h"

#define KOSE_MAX_BUF_SIZE_CMD (255)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif