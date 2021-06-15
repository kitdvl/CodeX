/*
  net_utilities.h
  --------------
  A bunch of useful networking functions that I keep using all the time.

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

#ifndef NET_UTILITIES_H
#define NET_UTILITIES_H

#include <common.h>
#if 0
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#ifndef	INADDR_NONE
#define	INADDR_NONE	0xffffffff	/* should be in <netinet/in.h> */
#endif

/*
  NOTE:
  all parameters should be passed in as host byte order. all functions
  here convert the host byte order to network byte order
*/

/* ---------- Networking Functions ------------*/

/* Creates a ipv4 stream socket. Exits on failure */
int utlnet_CreateIPV4StreamSocket();

/* Set socket to be reusable. Returns -1 on failure */
int utlnet_SetSocketReusable(const int sock_fd);

/* 
   Converts a hostname into an IP and sets it in the sockaddr struct. 
   Returns -1 on failure 
*/
int utlnet_SetIP(struct sockaddr_in *addr, const char *host_name);

/* Gets the hostname of the IP in the sockaddr_in struct */
struct hostent *utlnet_GetHostName(struct sockaddr_in *addr);

/* 
   Set the port number in a socket addr struct 
   Set the protocol family in the socket addr struct 
*/
void utlnet_SetPort(struct sockaddr_in *addr, const short port);
void utlnet_SetIPV4Protocol(struct sockaddr_in *addr);

/* 
   sets the IP, port and protocol for a IPV4 client connection.
   returns -1 on failure 
*/
int utlnet_InitIPV4ClientSockAddrStruct(struct sockaddr_in *addr, 
					const short port, 
					const char *host_name); 

/*
  sets the port, protocol and server ip. the serverIP is typically
  set to INADDR_ANY to allow kernel selection.
*/
void utlnet_InitIPV4ServerSockAddrStruct(struct sockaddr_in *addr,
					 const short port,
					 const unsigned int server_ip);

/*
  Sets up the listening socket for the given port and IP address 
  in servAddr. Also sets the queue backlog and the socket option
  if the port number needs to be reusable.
*/

#define REUSABLE        (char) 1
#define NOTRESUABLE     (char) 0

int utlnet_InitIPV4ServerSocket(const int sock_fd,
				struct sockaddr_in *addr,
				int sock_queue_backlog,
				char reusable);

/* 
   Connect to a remote host using an IPV4 sockaddr. 
   Returns -1 on failure 
*/
int utlnet_IPV4Connect(const int sock_fd, struct sockaddr_in *to_addr);

/* 
   Waits on a passive socket till it receives a connection. 
   Returns the connecting socket number.
*/
int utlnet_Accept(const int sock_fd, struct sockaddr_in *from_addr);

/* 
   Write/Read to the socket. 
   Returns bytes sent/read or -1 on error 
*/
int utlnet_WriteToSocket(int sock_fd, char *buffer, int length);
int utlnet_ReadFromSocket(int sock_fd, char *buffer, int length);

/* buffer should be at least n bytes long */
int utlnet_WritenBytesToSocket(int sock_fd, char *buffer, int n_bytes);
int utlnet_ReadnBytesFromSocket(int sock_fd, char *buffer, int n_bytes);

int utlnet_PeekAtnBytesFromSocket(int sock_fd, char *buffer, int n_bytes);

#endif
