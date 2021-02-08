#include <Windows.h>
#include "protocol_shof.h"
#include <mprotocol.h>
#include <util.h>
#include <m.h>

#if 0
02 10 0F 01 00 42 00 42 00 42 01 03 0A 00 00 00 00 02 0A 03 0A
#endif

void* on_shof_protocol_check(void* o, int8_t* b, int32_t sz, int32_t code)
{
  int32_t e = -1;
  TopRun* p = (TopRun*)o;


  //{
  //  uint8_t tmp[1024];
  //  sprintf(tmp, " >>> %02X %02X <<< \r\n", sz, *(b+2)+5);
  //  OutputDebugString(tmp);
  //}



	if ( code == 0 )
	{
    #if DEBUG_LOCAL
		display("on_shof_protocol_check",b,sz);
    #endif
  	p->callback(p->obj, MAKELONG(READ, XSOCKET), (void*)b, (void*)sz);
    //{
    //  uint8_t tmp[1024];
    //  int32_t i = 0;
    //  for ( i=0 ; i<sz ; i++ )
    //  {
    //    sprintf(&tmp[i*3], " %02X", (uint8_t)(b+i));
    //  }
    //  sprintf(&tmp[i*3], "\r\n");
    //  OutputDebugString(tmp);
    //}

	}
	else
	{
		if ( *(b+2)+5 == sz ) e = 0;
    else if ( sz < 0x14 ) e = -1;
    else e = -2;
	}
  return (void*)e;}
