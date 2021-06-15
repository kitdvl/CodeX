/*
  general_utilities.c
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "general_utilities.h"

/*
  Just calls a malloc except that it checks that the memory has actually
  been allocated. Exits from program if failure to allocate memory.
  Used to allocate memory for char *.
*/
void *
utl_GetMem(const int size)
{
    
    void *temp = malloc(size);
    
    if (!temp)
    {
	utl_HandleError("utl_GetMem");
    } 
    
    return temp;
}

/* 
   allocates memory and copies the src up to size amt 
*/
void *
utl_memcpy(const void *src, const int size_to_copy)
{
    void *dest;
    
    dest = utl_GetMem(size_to_copy);
    memcpy(dest, src, size_to_copy);
    
    return dest;
}

/*
  uses perror to print out the error and then exits
*/
void 
utl_HandleError(char *error_msg)
{
    perror(error_msg);
    exit(UTL_FAILURE);  
}

int 
utl_GenRandomInt(const int low, const int high)
{
    if(high < low)
    {
	utl_HandleError("utl_GenerateRandomInt");
    }
    
    if(high == low)
    {
	return low;
    }
    return ((rand() % (high + 1 - low)) + low);
}

/* 
   hex encodes and decodes strings 
   Returns length of output buffer.			
   encode returns an even length null terminated string.	
   decode expects an even length null terminated string.	
   memory will be allocated for out if outLen is 0	
*/
int utl_HexEncode(unsigned char *in, int in_len, char **out, int out_len)
{
    char map[17] = "0123456789ABCDEF";
    long i;
    
    if ((out_len != 0) && (2*in_len+1 > out_len)) 
    {
	fprintf(stderr, "utl_encode: Input stream too long.\n");
	return UTL_FAILURE;
    }

    if (out_len == 0) 
    {
	*out = utl_GetMem(2*in_len + 1);
    }
    
    for (i=0; i<in_len; i++) 
    {
	(*out)[i*2]   = map[(in[i]>>4)&0x0f];
	(*out)[i*2+1] = map[(in[i]   )&0x0f];
    }
    (*out)[i*2]='\0';
    return i*2;
}

/* rewrite this so that it allocates memory as well */
int utl_HexDecode(char *in, int in_len, unsigned char **out, int out_len)
{
    int v, i;
    char *from = in;
    
    /* checks if the number is odd */
    if (in_len&1) 
    {
	fprintf(stderr, "utl_decode: Cannot decode odd length data.\n");
	return UTL_FAILURE;
    }
  

    if(out_len == 0)
    {
	*out = utl_GetMem(in_len/2);
    }
    else if (out_len < in_len/2) 
    {
	fprintf(stderr, "utl_decode: Out buffer too short.\n");
	return UTL_FAILURE;
    }
    
    for (i=0; i<in_len/2; i++) (*out)[i]=0;
    
    for (i=0; (i<in_len) && (*from != '\0') && (!isspace(*from)); i++, from++) 
    {
	if ((*from >= '0') && (*from <= '9'))
	    v= *from-'0';
	else if ((*from >= 'A') && (*from <= 'F'))
	    v= *from-'A'+10;
	else if ((*from >= 'a') && (*from <= 'f'))
	    v= *from-'a'+10;
	else
	{
	    fprintf(stderr, "utl_decode: Cannot decode arguments.\n");
	    if(out_len == 0)
	    {
		free(*out);
	    }
	    return -1;
	}
	(*out)[i/2] |= v << (long)((!(i&1))*4);
    }
    
    return in_len/2;
}

/*
  Prints a char as hex. Converts the char to a unsigned int to avoid 
  sign extensions. This is used because printf does not support 
  printing 0x if the value is 0.
*/
void utl_PrintCharAsHex(char x)
{
    unsigned int byte=0;
    
    memcpy(&byte,&x,1);
    
    if(byte) 
    {
	printf(" %#.2x",byte);
    }
    else 
    {
	printf(" 0x00");
    }
}
