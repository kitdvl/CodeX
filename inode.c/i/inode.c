#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inode.h>
#include <code.x.h>

int32_t SocketCreate()
{
  //*(*(iohandler+1))(&h, (void*)MAKELONG(INIT               , XSOCKET),   instance,               (void*)0);
	//setMessage( p->h, (void*)MAKELONG(XM_DELAY_0         , XSOCKET),   (void*)"3000",               (void*)strlen("3000"));
	//setMessage( p->h, (void*)MAKELONG(XM_IP              , XSOCKET),   (void*)"192.168.0.252",       (void*)strlen("192.168.0.252"));
	//setMessage( p->h, (void*)MAKELONG(XM_PORT            , XSOCKET),   (void*)"80",                (void*)strlen("80"));
	//setMessage( p->h, (void*)MAKELONG(XM_PROTO           , XSOCKET),   (void*)"TCP",                (void*)strlen("TCP"));
	//setMessage( p->h, (void*)MAKELONG(XM_CSTYPE          , XSOCKET),   (void*)"CLIENT",             (void*)strlen("CLIENT"));
	//setMessage( p->h, (void*)MAKELONG(XM_CASTTYPE        , XSOCKET),   (void*)"UNICAST",            (void*)strlen("UNICAST"));
	//setMessage( p->h, (void*)MAKELONG(XM_ECHOMODE        , XSOCKET),   (void*)"0",                  (void*)strlen("0"));
	//setMessage( p->h, (void*)MAKELONG(XM_KEY             , XSOCKET),   (void*)"shinbaad@gmail.com", (void*)strlen("shinbaad@gmail.com"));
	//setMessage( p->h, (void*)MAKELONG(XM_TIMEOUT         , XSOCKET),   (void*)"1000",               (void*)strlen("1000"));
	//setMessage( p->h, (void*)MAKELONG(XM_BUFFER_PTR      , XSOCKET),   (void*)p->buf,               (void*)TR_BUF_SZ);
	//setMessage( p->h, (void*)MAKELONG(SYSTEM_CALLBACK    , XSOCKET),    TCPClientCallback, p);

  return 0;
}


int32_t SocketDestroy()
{
  return 0;
}


int32_t SocketWrite()
{
  return 0;
}

int32_t SocketRead()
{
  return 0;
}









int32_t SerialCreate()
{
  return 0;
}


int32_t SerialDestroy()
{
  return 0;
}


int32_t SerialWrite()
{
  return 0;
}

int32_t SerialRead()
{
  return 0;
}








int32_t HttpCreate()
{
  return 0;
}


int32_t HttpDestroy()
{
  return 0;
}


int32_t HttpWrite()
{
  return 0;
}

int32_t HttpRead()
{
  return 0;
}

