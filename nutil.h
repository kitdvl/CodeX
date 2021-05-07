/*****************************************************************************/
/*                                                                           */
/*            NCLab (Networked Control Lab) CORE version 1.0                 */
/*                                                                           */
/*****************************************************************************/
/*****************************************************************************/
/*                                                                           */
/*  File Name         : njson.h                                              */
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
#if 1 
#ifndef __NUTIL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __NUTIL_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined XWIN32
#include <Windows.h>
#endif

#if defined XWIN32
#define delay(a)     Sleep(a)
#endif

#if defined LINUX
#define delay(a)     usleep(a*1000)
#endif


#define BOX(a)        printf("+------------------------------------------------------------------------------+\r\n" \
                            "|                                                                              |\r\n"\
                            "| %-76s |\r\n" \
                            "|                                                                              |\r\n"\
                            "+------------------------------------------------------------------------------+\r\n", a)

int32_t asc_to_hex(uint8_t* src, uint8_t* dst);
int32_t hex_to_asc(uint8_t* src, uint8_t* dst);
int32_t to_raw(int8_t* in, int32_t isz, int8_t* out, int32_t* osz);
int32_t get_keyvalue(int8_t* in, int8_t* key, int8_t* val, int32_t* vsz);

#endif

#endif

