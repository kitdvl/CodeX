/*****************************************************************************/
/*                                                                           */
/*            DVLab (Data Visualization Lab) CORE version 1.0                */
/*                                                                           */
/*****************************************************************************/
/*****************************************************************************/
/*                                                                           */
/*  File Name         : inode.h                                              */
/*                                                                           */
/*  Description       :                                                      */
/*                                                                           */
/*                                                                           */
/*  Issues / Problems : None                                                 */
/*                                                                           */
/*  Revision History  :                                                      */
/*                                                                           */
/*        DD MM YYYY   Author(s)        Changes (Describe the changes made)  */
/*        17 03 2021   Shin Seunghyeok  Draft                                */
/*                                                                           */
/*****************************************************************************/
#ifndef __INODE_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __INODE_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#if defined WIN32
#define delay(a)  Sleep(a)
#endif
#if defined LINUX
#define delay(a)  usleep(a*1000)
#endif





#endif