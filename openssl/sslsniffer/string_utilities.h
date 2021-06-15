/*
  string_utilities.h
  --------------
  Written By: Eu-Jin Goh
  
  A bunch of string functions that I keep using all the time.
  
 */

#ifndef STRING_UTILITIES_H
#define STRING_UTILITIES_H

/* ----------- String functions ---------------------- */

/* wrapper around strcpy that allocates memory for the dest string */
char *utlstring_strcpy(const char *srcString);

/* wrapper around strcat that allocates memory for the concatenated string */
char *utlstring_strcat(const char *prefixString, const char *suffixString);

/* assumes that srand has already been called */
char *utlstring_GenRandomString(const int size);

#endif
