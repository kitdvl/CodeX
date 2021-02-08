#ifndef __UTIL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __UTIL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#include <stdio.h>
#include <stdint.h>


#define DEBUG_LOCAL   0


#define PREFIX        printf("        ");
#define PREFIXN      {static uint32_t i=0;printf("%08X|",i++);}
#define CRLF          printf("\r\n");

void raw_buffer(int8_t* b, int32_t sz, int8_t* o);
void display(int8_t* title, int8_t* b, int32_t sz);
void trace(const int8_t* fmt,...);
void memclr(void* a, int32_t sz);

//extern int32_t (*putMessage)(void* h, void* m, void* w, void* l);
//extern int32_t (*setMessage)(void* h, void* m, void* w, void* l);
//extern int32_t (*getMessage)(void* h, void* m, void* w, void* l);


#endif
