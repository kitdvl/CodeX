#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <Windows.h>

#include <m.h>
#include <mprotocol.h>
#include <protocol_shof.h>


static TopRun  tr;


int32_t to_raw(int8_t* in, int32_t isz, int8_t* out, int32_t* osz)
{
  for ( (*osz)=0 ; (*osz)<isz ; (*osz)++ )
  {
    sprintf((out+(*osz)*3), "%02X ", (uint8_t)*(in+(*osz)));
  }
  *(out+((*osz)*3)-1) = 0;
  return *osz;  
}




///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                       Application CALLBACK                        //////
//////                                                                   //////
//////                                                                   //////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************/
/*****************************************************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*****************************                ********************************/
/*******************************            **********************************/
/*********************************        ************************************/
/************************************   **************************************/
/************************************* ***************************************/
/*****************************************************************************/
int32_t fxWebSocketRouting(TopRun* p, int8_t* b, int32_t sz)
{
  int32_t e = 0;
  int32_t i = 0;
  int8_t  raw[8192];

  if ( p->pfdset[XWEBSOCKET] == 0 ) return ;

  to_raw((uint8_t*)b, (uint32_t)sz, raw, &e);

  for(i=0 ; i<FD_SETSIZE ; i++ )
  {
    if ( (p->pfdset[XWEBSOCKET]+i)->a[0] > 0 )
    {
      //p->setMessage(p->h, (void*)MAKELONG(FDSCRPTR, XWEBSOCKET), (void*)(p->pfdset[XWEBSOCKET]+i)->a[0], 0);
      //e = p->setMessage(p->h, (void*)MAKELONG(WRITE, XWEBSOCKET), (void*)b, (void*)sz);
      p->write(p->h, (p->pfdset[XWEBSOCKET]+i)->a[0], b, sz);

      p->log(&p->fp, "XWEBSOCKET", "Write to (%d:%d) %s\r\n", (p->pfdset[XWEBSOCKET]+i)->a[0], sz, raw);
    }
  }
  return e;
}

void* onProtocolSocketCallback(void* hwnd, void* msg, void* wparam, void* lparam)
{
  TopRun* p = (TopRun*)hwnd;

  uint8_t buf[4096] = {0};
  int32_t bsz = 0;

  switch(LOWORD((uint32_t)msg))
  {
    case READ:
      to_raw((uint8_t*)wparam, (uint32_t)lparam, buf, &bsz);
      p->log(&p->fp, "XSOCKET", "READ on Protocol (%d) %s\r\n", bsz, buf);

      fxWebSocketRouting(p, (uint8_t*)wparam, (uint32_t)lparam);
      break;
  }
  return 0;
}

void* onProtocolCallback(void* hwnd, void* msg, void* wparam, void* lparam)
{
  TopRun* p = (TopRun*)hwnd;

  switch(HIWORD((uint32_t)msg))
  {
    case XSOCKET:
      onProtocolSocketCallback(hwnd, msg, wparam, lparam);
      break;
  }
  return 0;
}





///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                         SYSTEM CALLBACK                           //////
//////                                                                   //////
//////                                                                   //////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************/
/*****************************************************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*****************************                ********************************/
/*******************************            **********************************/
/*********************************        ************************************/
/************************************   **************************************/
/************************************* ***************************************/
/*****************************************************************************/

void* DisplayFDSet(TopRun* p, int32_t id, int32_t fd, int8_t* title)
{
  uint8_t fds[FD_SETSIZE*8] = {0};
  uint32_t i =0;
  int8_t id_title[32] = {0};

  for ( i=0 ; i<FD_SETSIZE/4 ; i++ )
  {
    sprintf(&fds[i*6], "[%04d]", (uint32_t)(p->pfdset[id]+i)->a[0]);
  }

  sprintf(id_title, "%s",
            id==XSOCKET?"XSOCKET":
            id==XWEBSOCKET?"XWEBSOCKET":""
          );

  p->log(&p->fp, id_title, "FDSet ->  %s %04d->(%s) \r\n", title, fd, fds);

  return 0;
}


void* TCPServerCallback(void* hwnd, void* msg, void* wparam, void* lparam)
{
  TopRun* p = (TopRun*)hwnd;
  int32_t fd=0;

  uint8_t buf[4096] = {0};
  int32_t bsz = 0;
	static uint32_t bpos = 0;

  switch(LOWORD((uint32_t)msg))
  {
	case FDSCRPTR:
    p->log(&p->fp, "XSOCKET", "FD   (%d)\r\n", (uint32_t)wparam);
		break;

  case READ:
  	on_protocol_proc(shof_protocol_info, (int8_t*)wparam, (int32_t)lparam, p->protocol_buf, &bpos, on_shof_protocol_check, p);
    break;

    default:
		  if ( (uint32_t)lparam == 0xE000FD1A )
		  {
        p->getMessage(p->h, MAKELONG(FDSCRPTR,  XSOCKET), &fd, sizeof(fd));
        p->getMessage(p->h, MAKELONG(FDSCRPTRS, XSOCKET), &p->pfdset[XSOCKET], sizeof(p->pfdset[XSOCKET]));
        p->log(&p->fp, "XSOCKET", "FD   (%d)\r\n", (uint32_t)fd);
        DisplayFDSet(p, XSOCKET, fd, "Socket Client Connected");
		  }
		  else if ( ((uint32_t)lparam == 0xE000FDFA) || ((uint32_t)lparam == 0xE000101F) )
		  {
        p->getMessage(p->h, MAKELONG(FDSCRPTR,  XSOCKET), &fd, sizeof(fd));
        p->getMessage(p->h, MAKELONG(FDSCRPTRS, XSOCKET), &p->pfdset[XSOCKET], sizeof(p->pfdset[XSOCKET]));
        p->log(&p->fp, "XSOCKET", "FD   (%d)\r\n", (uint32_t)fd);
        DisplayFDSet(p, XSOCKET, fd, "Socket Client Disonnected");
		  }
      break;
  }
  return 0;
}


void* WebSocketServerCallback(void* hwnd, void* msg, void* wparam, void* lparam)
{
  TopRun* p = (TopRun*)hwnd;
  int32_t fd=0;

  switch(LOWORD((uint32_t)msg))
  {
    case READ:
      break;

	  case FDSCRPTR:
      p->log(&p->fp, "XWEBSOCKET", "FD   (%d)\r\n", (uint32_t)wparam);
		  break;

    default:
		  if ( (uint32_t)lparam == 0xE000FD1A )
		  {
        p->getMessage(p->h, MAKELONG(FDSCRPTR,  XWEBSOCKET), &fd, sizeof(fd));
        p->getMessage(p->h, MAKELONG(FDSCRPTRS, XWEBSOCKET), &p->pfdset[XWEBSOCKET], sizeof(p->pfdset[XWEBSOCKET]));
        p->log(&p->fp, "XWEBSOCKET", "FD   (%d)\r\n", (uint32_t)fd);
        DisplayFDSet(p, XWEBSOCKET, fd, "WebSocket Client Connected");
		  }
		  else if ( ((uint32_t)lparam == 0xE000FDFA) || ((uint32_t)lparam == 0xE000101F) )
		  {
        p->getMessage(p->h, MAKELONG(FDSCRPTR,  XWEBSOCKET), &fd, sizeof(fd));
        p->getMessage(p->h, MAKELONG(FDSCRPTRS, XWEBSOCKET), &p->pfdset[XWEBSOCKET], sizeof(p->pfdset[XWEBSOCKET]));
        p->log(&p->fp, "XWEBSOCKET", "FD   (%d)\r\n", (uint32_t)fd);
        DisplayFDSet(p, XWEBSOCKET, fd, "WebSocket Client Disonnected");
		  }
      break;
  }
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                              BASE                                 //////
//////                                                                   //////
//////                                                                   //////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************/
/*****************************************************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*********************************        ************************************/
/*****************************                ********************************/
/*******************************            **********************************/
/*********************************        ************************************/
/************************************   **************************************/
/************************************* ***************************************/
/*****************************************************************************/

void* TopCallback(void* hwnd, void* msg, void* wparam, void* lparam)
{
  TopRun* p = (TopRun*)hwnd;
  switch(HIWORD((uint32_t)msg))
  {
  case XSOCKET:
  	//tr.log(&tr.fp[XSOCKET], "XSOCKET", "%08X\r\n", (uint32_t)msg);
    TCPServerCallback(hwnd, msg, wparam, lparam);
    break;

  case XWEBSOCKET:
  	p->log(&p->fp, "XWEBSOCKET", "%08X\r\n", (uint32_t)msg);
    WebSocketServerCallback(hwnd, msg, wparam, lparam);
    break;
  }

  //tr.wrt(tr.hdl, 0, "1234", 4);

  return 0;
}


void* TCPServer(TopRun* p)
{
	p->setMessage(p->h, (void*)MAKELONG(XM_DELAY_0    , XSOCKET),   (void*)"3000",               (void*)strlen("3000"));
	p->setMessage(p->h, (void*)MAKELONG(XM_BUFFER_PTR , XSOCKET),   (void*)p->buf,               (void*)TR_BUF_SZ);
	//p->setMessage(p->h, (void*)MAKELONG(XM_BUFFER_SZ  , XSOCKET),   (void*)0,                    (void*)64);
	//p->setMessage(p->h, (void*)MAKELONG(XM_BUFFER_SZ  , XSOCKET),   0,                           (void*)1024);
	p->setMessage(p->h, (void*)MAKELONG(XM_IP         , XSOCKET),   (void*)"127.0.0.1",          (void*)strlen("127.0.0.1"));
	p->setMessage(p->h, (void*)MAKELONG(XM_PORT       , XSOCKET),   (void*)"7870",               (void*)strlen("7870"));
	p->setMessage(p->h, (void*)MAKELONG(XM_PROTO      , XSOCKET),   (void*)"TCP",                (void*)strlen("TCP"));
	p->setMessage(p->h, (void*)MAKELONG(XM_CSTYPE     , XSOCKET),   (void*)"SERVER",             (void*)strlen("SERVER"));
	p->setMessage(p->h, (void*)MAKELONG(XM_CASTTYPE   , XSOCKET),   (void*)"UNICAST",            (void*)strlen("UNICAST"));
	p->setMessage(p->h, (void*)MAKELONG(XM_ECHOMODE   , XSOCKET),   (void*)"0",                  (void*)strlen("0"));
	p->setMessage(p->h, (void*)MAKELONG(XM_KEY        , XSOCKET),   (void*)"shinbaad@gmail.com", (void*)strlen("shinbaad@gmail.com"));
	p->setMessage(p->h, (void*)MAKELONG(XM_TIMEOUT    , XSOCKET),   (void*)"7000",               (void*)strlen("7000"));
	p->setMessage(p->h, (void*)MAKELONG(ENABLE        , XSOCKET),  0, 0);

  return 0;
}



void* dmain(void* h, void** callback, void** iohandler, void** iocontroller, void** log, void** obj)
{

  *callback = TopCallback;
  *obj = &tr;

  tr.h = h;
  tr.write = *(iohandler+0);
  //tr.read = *(iohandler+1);
  tr.read = 0;

  tr.setMessage = *(iocontroller+0);
  tr.getMessage = *(iocontroller+1);
  tr.log = *log;


  tr.callback = onProtocolCallback;
  tr.obj = &tr;


  TCPServer(&tr);

  while( 1 )
  {
    Sleep(1);
  }

  return 0;
}
