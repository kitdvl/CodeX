/*
  general_utilities.h
  -------------------
  A bunch of useful functions that I keep using all the time.

  Copyright (C) 2000  Eu-Jin Goh

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
  USA. 
*/

/* necessary header files and defines */

#ifndef GENERAL_UTILITIES_H
#define GENERAL_UTILITIES_H

//#define UTL_ERROR_MESSAGE         "Error"
#define UTL_FAILURE -1
#define UTL_SUCCESS 1

/* ---------- General utility functions --------------- */

/* safe wrapper around malloc. Exits on failure */
void *utl_GetMem(const int size);

/* allocates memory and copies the src up to size amt */
void *utl_memcpy(const void *src, const int size_to_copy); 

/* error handler. calls perror and exits */
void utl_HandleError(char *error_msg);

/* assumes srand has already been called */
int utl_GenRandomInt(const int low, const int high);

/* 
   hex encodes and decodes strings 
   Returns length of output buffer.			
   encode returns an even length null terminated string.	
   decode expects an even length null terminated string.	
   memory will be allocated for out if outLen is 0	
*/
int utl_HexEncode(unsigned char *in, int in_len, char **out, int out_len);
int utl_HexDecode(char *in, int in_len, unsigned char **out, int out_len);

void utl_PrintCharAsHex(char x);


#endif
