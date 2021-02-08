#ifndef __MPROTOCOL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __MPROTOCOL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#include <stdint.h>


#define STX                0x02
#define ETX                0x03
#define PROTOCOL_SZ        15

int32_t on_protcol_check(uint8_t* se, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz, void* cbf(int8_t*, int32_t, int32_t));
int32_t on_protcol_check_HEX(uint8_t* se, int32_t maxsz, uint32_t* SR, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz);
int32_t on_protocol_proc(uint8_t* se, int8_t* b, int32_t sz, int8_t* o, int32_t* pos, void* cbf(void*,int8_t*, int32_t, int32_t), void* obj);


#endif
