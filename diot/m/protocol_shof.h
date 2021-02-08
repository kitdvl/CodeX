#ifndef __PROTOCOL_SHOF_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __PROTOCOL_SHOF_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#include <stdint.h>

#define EQUIP_IDS_COUNT        17

void* on_shof_protocol_check(void* o, int8_t* b, int32_t sz, int32_t code);


static uint8_t equip_ids[EQUIP_IDS_COUNT] = {1, 16, 0,};
static uint8_t shof_protocol_info[32] = {0x02, 0x03, 0x0A,};




#endif