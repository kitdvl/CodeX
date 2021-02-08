#include <util.h>
#include <stdarg.h>

#if defined XWIN32
#include <Windows.h>
#endif


void raw_buffer(int8_t* b, int32_t sz, int8_t* o)
{
  int32_t i = 0;

  for ( i=0 ; i<sz ;i++ )
  {
    if ( ((o+i)==0) || ((o+i+1)==0) || ((o+i+2)==0) )
    {
      i-=3;
      break;
    }
    sprintf(o+(i*3), "%02X ", (uint8_t)*(b+i));
  }
  *(o+(i*3)) = 0;
}

void display(int8_t* title, int8_t* b, int32_t sz)
{
  int32_t i = 0;

  CRLF;
  PREFIX;
  printf("**************************************************");
  CRLF;
  PREFIX;
  printf("* %-46s *", title);
  CRLF;
  PREFIX;
  printf("**************************************************");
  CRLF;
  PREFIX;
  for ( i=0 ; i<sz ; i++ )
  {
    if ( i &&  (i%8)==0 ) printf("  ");
    if ( i &&  (i%16)==0 )
    {
      CRLF;
      PREFIX;
    }
    printf(" %02X", (uint8_t)*(b+i));
  }
  CRLF;
  PREFIX;
  printf("--------------------------------------------------");
  CRLF;
  CRLF;
}

void trace(const int8_t* fmt,...)
{
  va_list args;
  int8_t _msg[512];
  #if defined LINUX
  PREFIXN;
  #endif
	va_start(args, fmt);
  #if defined XWIN32
  vsprintf(_msg, fmt, args);
  #else
	vfprintf(stderr,fmt, args);
  fflush(stderr);
  #endif
  va_end(args);

  #if defined XWIN32
  OutputDebugString(_msg);
  #endif
 
}


void memclr(void* a, int32_t sz)
{
  for ( sz-- ; sz >= 0  ; sz -- ) *((uint8_t*)a+sz) = 0;
}