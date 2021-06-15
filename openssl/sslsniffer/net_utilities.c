/*
  net_utilities.c
  --------------  
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

#include <common.h>

#include "net_utilities.h"
#include "general_utilities.h"

/* ------------- Networking Functions ------------- */

/*
  Creates a ipv4 stream socket
*/
int 
utlnet_CreateIPV4StreamSocket()
{
    int fd;
    
    /* set up the socket */  
    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
	utl_HandleError("utlnet_CreateIPV4StreamSocket");
    }
    
    return fd;
}

/* 
   Set socket to be reusable. 
   Returns -1 on failure 
*/
int 
utlnet_SetSocketReusable(int sock_fd)
{
    int sock_opt = 1;  
    
    /* 
       sets the socket so that it can be reused. this enables another
       application to make use of the same socket 
    */
    if(setsockopt(sock_fd, SOL_SOCKET,SO_REUSEADDR,
		  (void *)&sock_opt,sizeof(int)) < 0)
    {
	perror("utlnet_SetSocketReusable");
	return UTL_FAILURE;
    }
    return UTL_SUCCESS;
}

/*
  It first tries to convert it assuming that it is a dotted
  decimal number and if that fails, it uses gethostbyname to convert it. 
  
  Returns -1 on resolve failure.
*/
int 
utlnet_SetIP(struct sockaddr_in *addr, const char *host_name)
{
    unsigned long	in_addr;   /* Binary IP address */
    struct hostent *hostent_ptr;   /* used with gethostbyname() */
    
    /*
      First try to convert the host name as a dotted-decimal number.
      Only if that fails we call gethostbyname().
    */
    if((in_addr = inet_addr(host_name)) != INADDR_NONE)  
    {  
	addr->sin_addr.s_addr = in_addr; /* conversion succeeded */ 
    }
    else 
    {
	if ((hostent_ptr = gethostbyname(host_name)) == NULL) 
	{
	    //fprintf(stderr, "utlnet_SetIP: %s", hstrerror(h_errno));
      fprintf(stderr, "utlnet_SetIP: %s", strerror(errno));
	    return UTL_FAILURE;
	}
	
	memcpy((char *) &(addr->sin_addr), (char *)hostent_ptr->h_addr, 
	       hostent_ptr->h_length);
    } 
    
    return UTL_SUCCESS;
}

struct hostent *
utlnet_GetHostName(struct sockaddr_in *addr)
{
    return gethostbyaddr((char *)&(addr->sin_addr),sizeof(addr->sin_addr),
			 addr->sin_family); 
}

/*
  Set the port number in a socket addr struct
*/
void
utlnet_SetPort(struct sockaddr_in *addr, const short port)
{
    addr->sin_port = htons(port);
}

/*
  Set the protocol type in a socket addr struct
*/
void 
utlnet_SetIPV4Protocol(struct sockaddr_in *addr)
{
    addr->sin_family = AF_INET; 
}

/* 
   sets the IP, port and protocol for a IPV4 connection.
   returns -1 on failure 
*/
int 
utlnet_InitIPV4ClientSockAddrStruct(struct sockaddr_in *addr, 
				    const short port, 
				    const char *host_name)
{
    memset( (char*) addr, 0, sizeof(*addr));
    utlnet_SetPort(addr, port);
    utlnet_SetIPV4Protocol(addr);
    
    return utlnet_SetIP(addr, host_name);
}

/*
  sets the port, protocol and server ip. the serverIP is typically
  set to INADDR_ANY to allow kernel selection.
*/
void 
utlnet_InitIPV4ServerSockAddrStruct(struct sockaddr_in *addr,
				    const short port,
				    const unsigned int server_ip)
{
    memset( (char*) addr, 0, sizeof(*addr));
    utlnet_SetPort(addr, port);
    utlnet_SetIPV4Protocol(addr);
    addr->sin_addr.s_addr = htonl(server_ip); 
}

/*
  Sets up the listening socket for the given port and IP address 
  in servAddr. Also sets the queue backlog and the socket option
  if the port number needs to be reusable.
*/
int 
utlnet_InitIPV4ServerSocket(const int sock_fd,
			    struct sockaddr_in *addr,
			    int sock_queue_backlog,
			    char reusable)
{
    if(reusable && (utlnet_SetSocketReusable(sock_fd) == UTL_FAILURE))
    {
	exit(UTL_FAILURE);
    }  
    
    if(bind(sock_fd,(struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
	utl_HandleError("utlnet_InitIPV4ServerSocket");     
    }
    listen(sock_fd, sock_queue_backlog);  
    
    return UTL_SUCCESS;
}

/* 
   Connect to a remote host using an IPV4 sockaddr. 
   Returns -1 on failure 
*/
int 
utlnet_IPV4Connect(int sock_fd, struct sockaddr_in *to_addr)
{
    if(connect(sock_fd,(struct sockaddr *) to_addr, 
	       sizeof(struct sockaddr)) < 0)
    {
	return UTL_FAILURE;
    }
    
    return UTL_SUCCESS;
}

int 
utlnet_Accept(const int sock_fd, struct sockaddr_in *from_addr)
{
    int conn_fd;
    socklen_t size;
    
    size = sizeof(*from_addr);
    memset( (char *) from_addr, 0, size);
    
    if((conn_fd = accept(sock_fd,(struct sockaddr *) from_addr, &size)) < 0)
    {
	utl_HandleError("utlnet_Accept");
    }
    return conn_fd;
}

/* Write/Read to the socket. 
   Returns bytes sent/read or -1 on error */
int 
utlnet_WriteToSocket(int sock_fd, char *buffer, int length)
{
    int bytes_sent;
    
    if((bytes_sent = write(sock_fd, buffer, length)) < length)
    {
	perror("utlnet_WriteToSocket");
	return UTL_FAILURE;
    }
    return bytes_sent;  
}

int 
utlnet_ReadFromSocket(int sock_fd, char *buffer, int length)
{
    int bytes_read;
    
    if((bytes_read = read(sock_fd, buffer, length)) < 0)
    {      
	perror("utlnet_ReadFromSocket");
	return UTL_FAILURE;      
    }
    return bytes_read;  
}

int 
utlnet_WritenBytesToSocket(int sock_fd, char *buffer, int n_bytes)
{
    int bytes_sent;
    int total_sent = 0;

    while((bytes_sent = 
	     write(sock_fd, buffer + total_sent, n_bytes - total_sent)) > 0)
    {
	total_sent += bytes_sent;
	if(total_sent >= n_bytes)
	{
	    break;
	}
    }

    if(total_sent < n_bytes)
    {	
	/* this would be the error code returned by write */
	return bytes_sent;
    }

    return total_sent;    
}

int 
utlnet_ReadnBytesFromSocket(int sock_fd, char *buffer, int n_bytes)
{
    int bytes_read;
    int total_read = 0;

    while((bytes_read = 
	     read(sock_fd, buffer + total_read, n_bytes - total_read)) > 0)
    {
	total_read += bytes_read;
	if(total_read >= n_bytes)
	{
	    break;
	}
    }

    if(total_read < n_bytes)
    {	
	/* this would be the error code returned by read */
	return bytes_read;
    }

    return total_read;
}

int 
utlnet_PeekAtnBytesFromSocket(int sock_fd, char *buffer, int n_bytes)
{
    return recv(sock_fd, buffer, n_bytes, MSG_PEEK);
}
