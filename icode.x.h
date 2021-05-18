/*****************************************************************************/
/*                                                                           */
/*            NCLab (Networked Control Lab) CORE version 1.0                 */
/*                                                                           */
/*****************************************************************************/
/*****************************************************************************/
/*                                                                           */
/*  File Name         : icode.x.h                                            */
/*                                                                           */
/*  Description       : This file contains all the necessary constants ,     */
/*                      type definitions according to CAST specifications,	 */
/*                      common system headers.                               */
/*                                                                           */
/*                                                                           */
/*  Issues / Problems : None                                                 */
/*                                                                           */
/*  Revision History  :                                                      */
/*                                                                           */
/*        DD MM YYYY   Author(s)        Changes (Describe the changes made)  */
/*        18 03 2021   Shin Seunghyeok  Draft                                */
/*                                                                           */
/*****************************************************************************/
#ifndef __ICODE_X_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __ICODE_X_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#include <stdint.h>
#if __SSL_TLS__
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                          User Variable                            //////
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
enum
{
  ICODE_CALLBACK_CONNECTED = 0,
  ICODE_CALLBACK_DISCONNECTED,
  ICODE_CALLBACK_READ,
  ICODE_CALLBACK_READFROM,
  ICODE_CALLBACK_CGI_POST,
  ICODE_CALLBACK_CGI_GET,
  ICODE_CALLBACK_SSL_TLS,
  ICODE_CALLBACK_SSL_TLS_READ,
  ICODE_CALLBACK_SSL_TLS_WRITE,
  ICODE_CALLBACK_PRE_OPEN,
  ICODE_CALLBACK,
  ICODE_WRITE,
  ICODE_FD,
  ICODE_FDSET,
  ICODE_FUNCTIONS,
};


#if defined XWIN32
#pragma pack(1)
#endif
typedef struct
#if defined LINUX
__attribute__((packed))
#endif
{
  int32_t   a[4];  // fd sz  bp  fdp
} __iCodeFDSET;
#if defined XWIN32
#pragma pack()
#endif


#if defined XWIN32
#pragma pack(1)
#endif
typedef struct
#if defined LINUX
__attribute__((packed))
#endif
{
  int32_t max;
  __iCodeFDSET* fds;
} iCodeFDSET;
#if defined XWIN32
#pragma pack()
#endif

#if defined XWIN32
#pragma pack(1)
#endif
typedef struct
#if defined LINUX
__attribute__((packed))
#endif
{
  void* h;
  void* o;
  int32_t (*callback[ICODE_CALLBACK])(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);
  void* (*log)(int8_t* pfx, const int8_t* fmt,...);

  iCodeFDSET fdset;
} iCode;
#if defined XWIN32
#pragma pack()
#endif



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                            Socket                                 //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_fdset(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_readfrom(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_writeto(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __socket_close(void** h);

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                              HTTP                                 //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_fdset(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __http_close(void** h);


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                              HTTPD                                //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_fdset(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __httpd_close(void** h);

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                              HTTPS                                //////
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
#if __SSL_TLS__
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_fdset(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __https_close(void** h);
#endif
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                           WebSocket                               //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_fdset(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __ws_close(void** h);


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                             Serial                                //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __serial_fd(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __serial_read(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);


#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __serial_write(void* h, int32_t fd, int8_t* b, int32_t sz, void* moreinfo, void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __serial_open(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __serial_close(void** h);



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////                                                                   //////
//////                                                                   //////
//////                              SIFR                                 //////
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
#if defined __cplusplus
extern "C"
#endif
#if defined XWIN32 || defined WINCE
__declspec(dllexport)
#endif
int32_t __hmac(void** h, int8_t* argv, int32_t (*f[])(void*,int32_t,int8_t*,int32_t,void*,void*), void* o);

#endif