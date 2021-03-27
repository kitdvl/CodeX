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

#define CODEX                0xFFFF

#define SYSTEM_STATUS        0xFFFF
#define SYSTEM_VERSION       0xFFFE
#define SYSTEM_CALLBACK      0xFFFD
#define SYSTEM_CLEAR         0xFFFC
#define SYSTEM_LIBRARY       0xFFFB
#define SYSTEM_AUTHOR        0xFFFA
#define SYSTEM_MODULENAME    0xFFF9

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
  SIFR_HMAC_SHA256,
  MAX_SIFR,
  ENTIRE_SIFR = MAX_SIFR,
};

enum
{
  SIFR_PARAMETER = 0,
	SIFR_PARAM_KEY = SIFR_PARAMETER,
	SIFR_PARAM_VECTOR,
  SIFR_PARAM_INPUT,
  SIFR_PARAM_OUTPUT,
  SIFR_PARAM_OUTPUT_SZ,
  SIFR_PARAM_BUFFER_PTR,
  SIFR_PARAM_MACSZ,
  SIFR_PARAM_BITSZ,
	SIFR_PARAM_SIZE,
  SIFR_PARAM_DRBG_INIT,
  SIFR_PARAM_RESEED_PERIOD,
	SIFR_PARAM_NONCE,
	SIFR_PARAM_ENTROPY_0,
  SIFR_PARAM_ENTROPY_1,
  SIFR_PARAM_STRING_0,
  SIFR_PARAM_STRING_1,
  SIFR_PARAM_STRING_2,
  SIFR_PARAM_STRING_3,
  SIFR_PARAM_STRING_4,
  SIFR_PARAM_STRING_5,
  SIFR_PARAM_STRING_6,
  SIFR_PARAM_STRING_7,
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
  CFB_ENCODE,
  OFB_ENCODE,
  CTR_ENCODE,
  ECB_DECODE,
  CBC_DECODE,
  CFB_DECODE,
  OFB_DECODE,
  CTR_DECODE,
  CCM_ENCODE,
  CCM_DECODE,
  GCM_ENCODE,
  GCM_DECODE,
  CMAC,
  HASH,
  GENERATE,
  GENERATE_WITH_DF,
  SELF_CHECK,
  SELF_KAT_CHECK,
  SIFR_INIT,
  SIFR_RELEASE,
  SIFR_RESEED,
  SIFR_UPDATE,
  MAX_SIFR_STATUS,
  ENTIRE_SIFR_STATUS = MAX_SIFR_STATUS,
};





enum
{
  XMODULES = MAX_SIFR+1,
	XHTTP = XMODULES,
	XHTTPD,
	XPACKET,
	XPROTOCOL,
	XSERIAL,
	XSOCKET,
	XWEBSOCKET,
	XXML,
  XSYSTEM,
	MAX_MODULES,
  ENTIRE_MODULES = MAX_MODULES
};


enum
{
  XMODULE_PARAMETER = 0,
	XM_KEY = XMODULE_PARAMETER,
  XM_ENABLE,
  XM_SYNC,
  XM_DELAY_0,
  XM_DELAY_1,
  XM_DELAY_2,
  XM_TIMEOUT,
	XM_CONFIG,
  XM_DST_IP,
  XM_DST_PORT,
  XM_IP,
  XM_IFNAME,
  XM_PORT,
  XM_PROTO,
  XM_CSTYPE,
  XM_CASTTYPE,
  XM_URI,
  XM_HOME,
  XM_INDEX,
  XM_MAX_FD,
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
  XM_CLEAR,
  XM_USR,
  MAX_XMODULE_PARAMETER
};

enum
{
	XM_STATUS = MAX_XMODULE_PARAMETER,
  ENABLE,
  DISABLE,
  INIT,
  RELEASE,
  OPEN,
  CLOSE,
  CLOSE_SOCKET,
  BROADCAST,
	FDSCRPTR,
	FDSCRPTRS,
  WRITE,
  WRITETO,
  READ,
  READFROM,
  HTTP_URI,
  METHOD_GET,
  METHOD_POST,
  IDLE,
  READY,
  CONNECT,
  DISCONNECT,
	RUNNING,
	READING,
	WRITING,
  COMPLETE,
  REFERENCE,
  ASYNC_START,
  ASYNC_STOP,
  MAX_XM_STATUS
};




#define  E_NORMAL                              0
#define  E_SUCCESS                             E_NORMAL
#define  E_ABNORMAL                            0xE0000000
#define  E_NULL                                0xEFFFFFFF
#define  E_IO_ERROR                            0xE0000010
#define  E_READING                             0xE000101B
#define  E_READ_COMPLETE                       0xE000101A
#define  E_READ_FAIL                           0xE000101F
#define  E_WRITEING                            0xE000100B
#define  E_WRITE_COMPLETE                      0xE000100A
#define  E_WRITE_FAIL                          0xE000100F
#define  E_IO_BUFFER_PTR                       0xE00010B0
#define  E_IO_CLOSEING                         0xE000FDFB
#define  E_IO_CLOSE_COMPLETE                   0xE000FDFA
#define  E_IO_CLOSE_FAIL                       0xE000FDFF
#define  E_IO_OPENING                          0xE000FD0B
#define  E_IO_OPEN_COMPLETE                    0xE000FD0A
#define  E_IO_OPEN_FAIL                        0xE000FD0F
#define  E_IO_REMOTE_CONNECTING                0xE000FD1B
#define  E_IO_REMOTE_CONNECT_COMPLETE          0xE000FD1A
#define  E_IO_REMOTE_CONNECT_FAIL              0xE000FD1F
#define  E_CLIENT_CONNECTING                   0xE000FDCB
#define  E_CLIENT_CONNECT_COMPLETE             0xE000FDCA
#define  E_CLIENT_CONNECT_FAIL                 0xE000FDCF
#define  E_CLIENT_BUFFER_PTR                   0xE000BF0B
#define  E_ENCODEING                           0xE000ECDB
#define  E_ENCODE_COMPLETE                     0xE000ECDA
#define  E_DECODEING                           0xE000DCDB
#define  E_DECODE_COMPLETE                     0xE000DCDA


#define  E_ABNORMAL_STATUS                     0xEA000001
#define  E_CRITICAL_ERROR                      0xEA000002


#define  E_ARIA_KEY_NULL                       0xECA10001
#define  E_ARIA_KEY_SIZE                       0xECA10002
#define  E_ARIA_IV_NULL                        0xECA10003
#define  E_ARIA_IV_SIZE                        0xECA10004
#define  E_ARIA_CTR_NULL                       0xECA10005
#define  E_ARIA_CTR_SIZE                       0xECA10006

#define  E_LEA_KEY_NULL                        0xECA20001
#define  E_LEA_KEY_SIZE                        0xECA20002
#define  E_LEA_IV_NULL                         0xECA20003
#define  E_LEA_IV_SIZE                         0xECA20004
#define  E_LEA_CTR_NULL                        0xECA20005
#define  E_LEA_CTR_SIZE                        0xECA20006

#define  E_SEED_KEY_NULL                       0xECA30001
#define  E_SEED_KEY_SIZE                       0xECA30002
#define  E_SEED_IV_NULL                        0xECA30003
#define  E_SEED_IV_SIZE                        0xECA30004
#define  E_SEED_CTR_NULL                       0xECA30005
#define  E_SEED_CTR_SIZE                       0xECA30006

#define  E_HIGHT_KEY_NULL                      0xECA40001
#define  E_HIGHT_KEY_SIZE                      0xECA40002
#define  E_HIGHT_IV_NULL                       0xECA40003
#define  E_HIGHT_IV_SIZE                       0xECA40004
#define  E_HIGHT_CTR_NULL                      0xECA40005
#define  E_HIGHT_CTR_SIZE                      0xECA40006














#endif