#ifndef __M_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __M_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#include <code.x.h>

#define TR_BUF_SZ      1024

#if defined WIN32
#pragma pack(1)
#endif
typedef struct
#if defined LINUX
__attribute__((packed))
#endif
{
  int   a[4];  // fd sz  bp  fdp
} trFDSET;
#if defined WIN32
#pragma pack()
#endif

typedef struct
{
  void* h;
  void* (*read)(void* h, int fd, char* b, int s);
  void* (*write)(void* h, int fd, char* b, int s);

  void* (*setMessage)(void* h, void* msg, void* wparam, void* lparam);
  void* (*getMessage)(void* h, void* msg, void* wparam, void* lparam);

	void* (*log)(void* fp, int8_t* pfx, const int8_t* fmt,...);

  void* (*callback)(void*,void*,void*,void*);
  void*  obj;

  FILE* fp;
  uint8_t buf[TR_BUF_SZ];
  uint8_t protocol_buf[4096];

  trFDSET* pfdset[MAX_MODULES];
} TopRun;




#if defined __cplusplus
extern "C"
#endif
#if defined WIN32 || defined WINCE
__declspec(dllexport)
#endif
void* dmain(void* hdl, void** callback, void** iohandler, void** iocontroller, void** log, void** obj);

#endif