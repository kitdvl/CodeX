/*****************************************************************************/
/*                                                                           */
/*            DVLab (Data Visualization Lab) CORE version 1.0                */
/*                                                                           */
/*****************************************************************************/
/*****************************************************************************/
/*                                                                           */
/*  File Name         : code.x.h                                             */
/*                                                                           */
/*  Description       :                                                      */
/*                                                                           */
/*                                                                           */
/*  Issues / Problems : None                                                 */
/*                                                                           */
/*  Revision History  :                                                      */
/*                                                                           */
/*        DD MM YYYY   Author(s)        Changes (Describe the changes made)  */
/*        25 02 2019   Shin Seunghyeok  Draft                                */
/*                                                                           */
/*****************************************************************************/
#ifndef __CODE_X_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __CODE_X_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__



#if defined LINUX
#define MAKEWORD(a,b)      ((a&0x00FF)|((b&0x00FF)<<8))
#define MAKELONG(a,b)      ((a&0x0000FFFF)|((b&0x0000ffff)<<16))
#define LOWORD(l)           (l&0x0000FFFF)
#define HIWORD(l)          ((l&0xFFFF0000)>>16)
#define LOBYTE(w)           (w&0x00FF)
#define HIBYTE(w)          ((w&0xFF00)>>8)
#endif

#define SYSTEM_STATUS        0xFFFF

/// <summary>
/// MSG HIWORD SYSTEM & SIFR
/// </summary>
enum
{
  SIFR = 0,
  SIFR_ARIA = SIFR,
  SIFR_HIGHT,
  SIFR_LEA,
  SIFR_SEED,
  SIFR_LSH256,
  SIFR_LSH512,
  SIFR_SHA256,
  SIFR_DRBG,
  SIFR_HMAC,
  MAX_SIFR,
};

enum
{
  SIFR_PARAMETER = 0,
	SIFR_PARAM_KEY = SIFR_PARAMETER,
	SIFR_PARAM_IV,
  SIFR_PARAM_COUNTER,
  SIFR_PARAM_INPUT,
  SIFR_PARAM_OUTPUT,
  SIFR_PARAM_BITSZ,
	SIFR_PARAM_SIZE,
	SIFR_PARAM_NONCE,
	SIFR_PARAM_ENTROPY_0,
  SIFR_PARAM_ENTROPY_1,
  SIFR_PARAM_STRING,
  SIFR_PARAM_ADD_INPUT,
  SIFR_PARAM_USE_INTERNAL_NONCE,
  SIFR_PARAM_USE_INTERNAL_ENTROPY_0,
  SIFR_PARAM_USE_INTERNAL_ENTROPY_1,
  SIFR_PARAM_CLEAR,
  MAX_SIFR_PARAMETER,
};

enum
{
	SIFR_STATUS = MAX_SIFR_PARAMETER,
  ECB_ENCODE,
  CBC_ENCODE,
  CTR_ENCODE,
  ECB_DECODE,
  CBC_DECODE,
  CTR_DECODE,
  HASH,
  GENERATE,
  GENERATE_WITH_DF,
  MAX_SIFR_STATUS
};





enum
{
  XMODULES = MAX_SIFR,
	XHTTP = XMODULES,
	XHTTPD,
	XPACKET,
	XPROTOCOL,
	XSERIAL,
	XSOCKET,
	XWEBSOCKET,
	XXML,
  XSYSTEM,
	MAX_MODULES
};


enum
{
  XMODULE_PARAMETER = 0,
	XM_KEY = XMODULE_PARAMETER,
  XM_ENABLE,
  XM_DELAY_0,
  XM_DELAY_1,
  XM_DELAY_2,
	XM_CONFIG,
  XM_IP,
  XM_IFNAME,
  XM_PORT,
  XM_PROTO,
  XM_CSTYPE,
  XM_CASTTYPE,
  XM_URI,
  XM_HOME,
  XM_INDEX,
  XM_DESC,
  XM_BAUDRATE,
  XM_DATABIT,
  XM_STOPBIT,
  XM_PARITYBIT,
  XM_BLOCKMODE,
  XM_ECHOMODE,
  XM_AP_SSID,
  XM_AP_PW,
  XM_EST,
  XM_ESTID,
  XM_EPT,
  XM_ESI,
  XM_ESP,
  XM_COUNT,
  XM_BUFFER_PTR,
  XM_BUFFER_SZ,
  XM_CLEAR,
  XM_USR,
  MAX_XMODULE_PARAMETER
};

enum
{
	XM_STATUS = MAX_XMODULE_PARAMETER,
  ENABLE,
  DISABLE,
  ENABLED,
  DISABLED,
  INIT,
  RELEASE,
  OPEN,
  CLOSE,
  BROADCAST,
	FDSCRPTR,
	FDSCRPTRS,
  WRITE,
  READ,
  IDLE,
  READY,
  CONNECT,
  DISCONNECT,
	RUNNING,
	READING,
	WRITING,
  COMPLETE,
  ASYNC_START,
  ASYNC_STOP,
  MAX_XM_STATUS
};






























#endif