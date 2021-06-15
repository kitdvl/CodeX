/*
  string_utilities.c
  --------------
  Written By: Eu-Jin Goh
  
  A bunch of useful functions that I keep using all the time.  
 */

/* necessary header files and defines */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "string_utilities.h"
#include "general_utilities.h"

/* ------------- String Functions ----------------- */

/* 
   wrapper around strcpy that allocates memory for the dest string 
*/
char *
utlstring_strcpy(const char *srcString)
{
  char *destBuffer;

  if(srcString == NULL)
    {
      fprintf(stderr, "utl_strcpy: NULL string passed as argument\n");
      return NULL;
    }

  destBuffer = utl_GetMem(strlen(srcString) + 1);
  strcpy(destBuffer, srcString);
  
  return destBuffer;
}

/* 
   wrapper around strcat that allocates memory for the concatenated string 
*/
char *
utlstring_strcat(const char *prefixString, const char *suffixString)
{
  char *concat;

  if(prefixString == NULL || suffixString == NULL)
    {
      return NULL;
    }

  concat = utl_GetMem(strlen(prefixString) + strlen(suffixString) + 1);
  strcpy(concat, prefixString);
  strcat(concat, suffixString);

  return concat;
}

/* assumes that srand has already been called */
char *
utlstring_GenRandomString(const int size)
{
  char *result;
  int rchar;
  int i;

  result = utl_GetMem(size + 1);


  for(i = 0; i < size; i++)
    {
      /* first determine upper or lower case */
      rchar = rand() % 2;
      
      if(rchar)
	{
	  /* generate lower case */
	  result[i] = (char) ((rand() % 26) + 'a');
	}
      else 
	{
	  /* generate upper case */
	  result[i] = (char) ((rand() % 26) + 'A');
	}
    }
  result[size] = '\0';
  
  return result;
}
