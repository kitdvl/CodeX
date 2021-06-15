/*
  SSL Sniffer V1.21.
  ----------------------------------------------
  Written by: Eu-Jin Goh (eujin@cs.stanford.edu)
              Stanford University October 2000
	      
  Copyright (C) 2000  Eu-Jin Goh
	      
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
  02111-1307, USA.

  ----------------------------------------------

  See the README for program notes.
*/

#include <common.h>
#if defined LINUX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif



#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>


#include "sslsniffer.h"
#include "general_utilities.h"
#include "net_utilities.h"

#ifndef	INADDR_NONE
#define	INADDR_NONE	0xffffffff	/* should be in <netinet/in.h> */
#endif

/* function declarations */
static int PopulateArgvParams(argv_params *argv_p, int argc, char **argv);
static int InitSSLSniffer(struct sockaddr_in *servAddr, argv_params *argv_p);

static int WaitForConnection(int listenfd, argv_params *argv_p);
static int WaitForClient(struct sockaddr_in *fromAddr, int listenfd);
static int ParseCONNECT(char *buffer, struct sockaddr_in *toAddr, 
			 int client_fd);


static void DoOneSSLConnection(int client_fd, int server_fd);
static void Setfds(fd_set *fds, ssl_connection *ssl_conn);

static int ClientHelloRead(ssl_connection *ssl_conn);
static int ReadOneTLSRecord(ssl_connection *ssl_conn);
static int ReadOneSSL2Record(ssl_connection *ssl_conn);
static int ServerRead(ssl_connection *ssl_conn);
static int ClientRead(ssl_connection *ssl_conn);
/* 
   before calling this function, the record len of the ssl_conn should
   be the total num of bytes to be read including the previously read
   bytes
*/
static int ReadRecordData(ssl_connection *ssl_conn, 
			  char *prev_read_buf, 
			  int num_prev_read_bytes);


/* SSL3 / TLS */
static int ProcessTLSPacketType(ssl_connection *ssl_conn);
static void ProcessTLSAlertMessage(ssl_connection *ssl_conn);
static void ProcessTLSHandshakeMessage(ssl_connection *ssl_conn);

static void ProcessTLSClientHello(char *buffer);
static char *ProcessTLSHello(char *buffer);

static void ProcessServerHello(char *buffer, ssl_connection *ssl_conn);
static void ProcessTLSCipherSuite(char byte1, char byte2);
static void DetermineTLSKeyExchangeAlgorithm(char byte1, ssl_connection *ssl_conn);

static void ProcessCertificateChain(char *buffer, ssl_connection *ssl_conn);
static void ProcessCertificate(X509 *x);
//static void PrintCertificateInfo(UTL_CERT_INFO *buf, EVP_PKEY *key);

static void ProcessCertificateRequest(char *buffer, ssl_connection *ssl_conn);

static void ProcessTLSServerKeyExchange(char *buffer, ssl_connection *ssl_conn);
static char *ExtractParams(char *params, char *type);

static void ProcessTLSClientKeyExchange(char *buffer, ssl_connection *ssl_conn);


/* SSL2 */
static int ProcessOneSSL2Record(ssl_connection *ssl_conn);
static void ProcessSSLV2ClientMasterKey(ssl_connection *ssl_conn);
static void ProcessSSLV2OneCipherSuite(char byte1, char byte2, char byte3);
static void ProcessSSLV2ClientHello(ssl_connection *ssl_conn);
static void ProcessSSLV2CipherSuiteData(char *cipher_suite_data, 
					unsigned short data_len);
static int IsV2ClientHello(char *record_hdr);
static void ProcessSSLV2ServerHello(ssl_connection *ssl_conn);
static void ProcessSSLV2Error(ssl_connection *ssl_conn);

#if 0
static void ProcessSSLV2ClientFinished(ssl_connection *ssl_conn);
static void ProcessSSLV2ClientCertificate(ssl_connection *ssl_conn);
#endif

/* Utility functions */
void CloseSocket(int sock);
short TwoBytesToInt(char *buffer);
unsigned int ThreeBytesToInt(char *buffer);

/* main program */
int
main (int argc, char **argv)
{
    struct sockaddr_in serv_addr; /* proxy server address */
    int sock;                     /* our socket handler */
    argv_params argv_p;

    /* get all the params first */
    if(PopulateArgvParams(&argv_p, argc, argv) < 0)
    {
	return FAILURE;    
    }
   
    sock = InitSSLSniffer(&serv_addr, &argv_p);

    /* loop till a client connects successfully */
    while(1) 
    {
	if(WaitForConnection(sock, &argv_p) < 0)
	{
	    printf("\n--------------------------------------------------------\n\n");
	}
    }
    CloseSocket(sock);
    return SUCCESS;
}

static int 
PopulateArgvParams(argv_params *argv_p, int argc, char **argv)
{
    int num_args = argc - 1;
    char **cur_argv = &(argv[1]);
    int change;

    /* set it to the default port first */
    argv_p->local_port = (short) DEFAULT_PORT;
    argv_p->proxy = 1;

    /* iterate over the arguments, setting the appropriate fields */
    for(num_args = argc - 1; num_args > 0; )
    {
	    if(strcmp(cur_argv[0], SNIFFER_ARGV_PORT) == 0)
	    {
		/* next argv should be the the port */
		if(num_args < 2)
		{
		    goto error;
		}
		argv_p->local_port = (short) atoi(cur_argv[1]);
		change = 2;
	    }
	    else if(strcmp(cur_argv[0], SNIFFER_ARGV_NO_PROXY) == 0)
	    {
	        /* need to specify the hostname and remote port */
		if(num_args < 3)
		{
		    goto error;
		}
		argv_p->remote_port = (short) atoi(cur_argv[1]);
		argv_p->remote_host_name_or_ip = cur_argv[2];
		argv_p->proxy = 0;
		change = 3;
	    }
	    else
	    {
		goto error;
	    }
	    num_args -= change;
	    cur_argv += change;
    }

    return 1;

 error:
    printf("Usage: sslsniffer [-p <local port>] [-np <remote port> <remote hostname/ip>]\n");
    return -1;
}

/*
  Initializes the server socket. The socket is set to be reusable.  If
  no port number is specified, the default one is used.

  returns the socket number that it is listening to.
*/
static int 
InitSSLSniffer(struct sockaddr_in *serv_addr, argv_params *argv_p)
{ 
    int listen_fd;
    
    /* first set up the listening socket */   
    
    listen_fd = utlnet_CreateIPV4StreamSocket();
    
    utlnet_InitIPV4ServerSockAddrStruct(serv_addr, argv_p->local_port, 
					INADDR_ANY);
    
    (void) utlnet_InitIPV4ServerSocket(listen_fd, serv_addr, 5, REUSABLE);
    
    /* print credits! */
    printf("\nSSLV3/TLS Sniffer 1.1 written by Eu-Jin Goh\n"
	   "Stanford University Applied Crypto Group\n");
    printf("\nSSL Sniffer listening on port number %d\n", 
	   argv_p->local_port);
    
    /* print out an extra line of info for no proxy connections */
    if(argv_p->proxy)
    {
	printf("\n");
    }
    else
    {
	printf("Will connect incoming connections to %s on port %d\n\n",
	       argv_p->remote_host_name_or_ip, argv_p->remote_port);
    }

    return listen_fd;
}


/*
  waits till a client connects to the proxy server. It first tries to
  read from the client socket and parse the information assuming that
  the first request is a CONNECT command.
  
  It then uses the information contained in the request to connect to
  the server and if successful, replies to the client with a 200
  status code.  Otherwise, it replies with a 400 if the request is not
  the CONNECT command in the proper format and a 404 if it cannot
  connect to the dest.

  returns 0 or 1 depending on whether the client connected
  successfully.
*/
static int
WaitForConnection(int listen_fd, argv_params *argv_p)
{
    int bytes_read=0;       
    int client_fd;           /* socket for the client */
    int server_fd = -1;
    struct sockaddr_in from_addr;
    struct sockaddr_in to_addr;
    char buffer[BUFFER_SIZE];
    
    /* blocks till a client tries to connect to the proxy server */
    client_fd = WaitForClient(&from_addr, listen_fd);

    /* if the no_proxy flag was not given, we assume a CONNECT will be sent */ 
    if(argv_p->proxy)
    {    
        /* read and print from client socket */
        if((bytes_read = utlnet_ReadFromSocket(client_fd, buffer, BUFFER_SIZE)) < 0)
	{
	    goto error;
	}
	
	buffer[bytes_read] = '\0'; /* null terminate the string */
	printf("\nRead %d bytes from CONNECT request:\n%s", bytes_read, buffer);
    
	/* obtain dest address and port */
	if(ParseCONNECT(buffer, &to_addr, client_fd) < 0)
	{
	    goto error;   
	}
    }
    else /* otherwise, this is a direct connection */
    {
	if(utlnet_InitIPV4ClientSockAddrStruct(&to_addr, 
					       argv_p->remote_port,
					       argv_p->remote_host_name_or_ip) < 0)
	{
	    goto error;
	}
    }
    
    /* connect to destination */
    server_fd = utlnet_CreateIPV4StreamSocket();
    if(utlnet_IPV4Connect(server_fd, &to_addr) < 0)
    {
	perror("WaitForConnection");
	
	/* only send back a 404 if this is a proxied connection */
	if(argv_p->proxy)
	{
	    sprintf(buffer,"HTTP/1.0 404 Unable to Connect\r\n\r\n");
	    printf("Writing to socket: %s",buffer);	
	    (void) utlnet_WriteToSocket(client_fd, buffer, strlen(buffer));
	}
	goto error;
    }
    
    /* 
       once connected, reply to client that connection is established.
       only send it back if this is a proxied connection
    */
    if(argv_p->proxy)
    {
	sprintf(buffer,"HTTP/1.0 200 Connection Established\r\n\r\n");
	printf("Sending back to client: %s",buffer);
	if(utlnet_WriteToSocket(client_fd, buffer, strlen(buffer)) < 0)
	{
	    goto error;
	}
    }

    /* handles this TLS Connection */
    DoOneSSLConnection(client_fd, server_fd);
    
    return 1;
    
 error:
    CloseSocket(client_fd);
    if(server_fd >= 0)
    {
	CloseSocket(server_fd);
    }
    return -1;
}


/*
  accept blocks till a client tries to connect to the proxy server. it
  then prints out where the connection is originating from (hostname
  and port)

  returns the socket descriptor for the connection.
*/
static int 
WaitForClient(struct sockaddr_in *from_addr, int listen_fd)
{
    int conn_fd;
    struct hostent *name;
    
    conn_fd = utlnet_Accept(listen_fd, from_addr);
    
    /* print out where connection originates from */
    name = utlnet_GetHostName(from_addr);
    
    if(name != NULL)
    {
	printf("--------------------------------------------------------\n");   
	printf("Received connection from %s, port %d\n",
	       name->h_name,ntohs(from_addr->sin_port));
    }
    else 
    {
	printf("Cannot resolve IP of incoming connection\n");
    }
    
    return conn_fd;
}


/*
  Parses the first message that is sent to the proxy server. It is
  assumed to be in the following format: CONNECT IPADDRESS:PORT

  extracts the IPADDRESS and stores it in the sockaddr_in as a binary
  address, together with the port number.

  returns 1 or 0 depending on whether it was successful in parsing. 
*/
int
ParseCONNECT(char *buffer, struct sockaddr_in *to_addr, int client_fd)
{
    char *start,*end;
    char *host_name = NULL;
    char *port = NULL;
    char temp[BUFFER_SIZE];
    int return_value = 1;
    
    start = strchr(buffer, ' '); /* location of first space */
    end = strchr(buffer, ':');   /* location of ':' */
    
    /* check that the connect request conforms to the expected spec */
    if(start == NULL || end == NULL)
    {
	sprintf(temp,"HTTP/1.0 400 Bad Request\r\n\r\n");
	printf("Sending to client: %s", temp);
	utlnet_WriteToSocket(client_fd, temp, strlen(temp));
	
	return_value = -1;
	goto error;
    }
    
    /* obtain the host_name */
    host_name = (char *) utl_GetMem((end - start) / sizeof(char));
    ++start; /* makes it point to the first char */
    strncpy(host_name, start, end-start);
    host_name[end-start] = '\0';
    
    /* obtain the port number */
    start = strchr(end, ' ');
    port = (char *) utl_GetMem((start - end) / sizeof(char));
    ++end;
    strncpy(port, end, start - end);
    port[start-end] = '\0';
    
    printf("Destination hostname is %s, port is %s\n", host_name, port);
    
    /* initialize fields in sockaddr_in */
    if(utlnet_InitIPV4ClientSockAddrStruct(to_addr, atoi(port), host_name) < 0)
    {      
	return_value = -1;
	goto error;
    }  
    
 error:
    free(host_name);
    free(port);
    return return_value;
}

/*
  Performs the proxy operations for one TLS connection. Sits in the
  middle the connection and transfers the data from client to server
  and vice versa.

  Processes the data that the client and server send to each other to
  determine at which stage of the TLS protocol the connection is in.

  the ssl_conn is always set to assume a client to server connection
*/

static void 
DoOneSSLConnection(int client_fd, int server_fd)
{
    int bytes_read = 0;
    fd_set fds;  
    ssl_connection ssl_conn;

    /* 
       initialize the ssl_conn to default values for TLS
       default is doing a client to server connection
    */
    ssl_conn.client_fd = client_fd;
    ssl_conn.server_fd = server_fd;
    ssl_conn.read_fd = ssl_conn.client_fd;
    ssl_conn.write_fd = ssl_conn.server_fd;     
    ssl_conn.recv_client_hello = 0;
    ssl_conn.recv_server_hello = 0;
    ssl_conn.recv_change_cipher[SERVER_RECV_CHANGE_CIPHER] = 0;
    ssl_conn.recv_change_cipher[CLIENT_RECV_CHANGE_CIPHER] = 0;   
    ssl_conn.recv_change = 
	&(ssl_conn.recv_change_cipher[CLIENT_RECV_CHANGE_CIPHER]); 

    /* these are the default values for SSL2 */
    ssl_conn.ssl2_packets_encrypted = 0;

    /* 
       sits in this while loop transferring and processing data till one of 
       the sockets close 
    */
    while(true)
    {
	Setfds(&fds, &ssl_conn);
	switch(select( MAX(ssl_conn.client_fd, ssl_conn.server_fd) + 1, 
		       &fds, NULL, NULL, NULL))
	{

	case -1: 

	    /* select error */
	    perror("DoOneSSLConnection"); 
	    return; 

	default:

	    /* figure out which socket has stuff to read and take the
	       appropriate action */
	    if(FD_ISSET(ssl_conn.server_fd, &fds))
	    {
		printf("\n\nReading from SERVER socket\n");;
		bytes_read = ServerRead(&ssl_conn);
	    }
	    else if(FD_ISSET(ssl_conn.client_fd, &fds))
	    {
		printf("\n\nReading from CLIENT socket\n");

		/* 
		   client hellos are handled differently, we want to pull
		   off the protocol versions and stuff like that here 
		*/
		if(!ssl_conn.recv_client_hello)
		{		    
		    bytes_read = ClientHelloRead(&ssl_conn);
		}
		else
		{
		    bytes_read = ClientRead(&ssl_conn);
		}
	    }
	}
	
	/* either error or no bytes read */
	if(bytes_read <= 0)
	{
	    printf("\nClose connections\n\n");
	    CloseSocket(ssl_conn.server_fd); 
	    CloseSocket(ssl_conn.client_fd);
	    break;
	}

    }
}

/*
  Sets the fd_set for use in the select function
*/
static void 
Setfds(fd_set *fds, ssl_connection *ssl_conn)
{
    FD_ZERO(fds);
    FD_SET(ssl_conn->server_fd, fds);
    FD_SET(ssl_conn->client_fd, fds);
}

/*
  Handles client hellos. This needs to be separated out from the
  normal processing because of the V23 client hellos that get sent.
  We figure out whether it's a V2 or V3 connection here.

  It also writes the entire packet to the hello socket when it is done
  processing it.

  returns the number of bytes written to the server.
*/
static int
ClientHelloRead(ssl_connection *ssl_conn)
{
    char record_hdr_buf[TLS_RECORD_HEADER_SIZE];
    int bytes_read = 0;

    /* we need to figure out whether its V2, V3 or V23 */
    
    /* pull off the first three bytes */
    if((bytes_read = 
	utlnet_ReadnBytesFromSocket(ssl_conn->client_fd, record_hdr_buf, TLS_RECORD_HEADER_SIZE)) < 0)
    {
	goto end;
    }               

    /* first check if it's a V2 client hello */ 
    if(IsV2ClientHello(record_hdr_buf))
    {
	/* read the rest of the record from the socket */
	    ssl_conn->record_len = (((record_hdr_buf[0] & 0x7f) << 8) 
				    | ((unsigned char) record_hdr_buf[1]))
		                   + SSL2_2BYTE_RECORD_HEADER_SIZE;

	if((bytes_read = ReadRecordData(ssl_conn, record_hdr_buf, TLS_RECORD_HEADER_SIZE)) < 0)
	{
	    goto end;
	}
	
	/* set the right values in the ssl_conn */
	if(ssl_conn->record[SSL2_CLIENT_HELLO_MAJOR_VER_OFFSET] == TLS_MAJOR)
	{
	    ssl_conn->ssl_version = VERSION_SSL3;
	}
	else
	{
	    ssl_conn->ssl_version = VERSION_SSL2;
	}

	/* do the printing out */
	ProcessSSLV2ClientHello(ssl_conn);	
    }
    else
    {
	/* if not ssl2, assume this is a ssl3/tls packet */
	
	/* read the rest of the record */
	ssl_conn->record_len = TwoBytesToInt(&(record_hdr_buf[TLS_RECORD_LENGTH_OFFSET]))
                               + TLS_RECORD_HEADER_SIZE;
	if((bytes_read = ReadRecordData(ssl_conn, record_hdr_buf, TLS_RECORD_HEADER_SIZE)) 
	     < 0)
	{
	    goto end;
	}

	/* verify that the major version is right */
	if(ssl_conn->record[TLS_RECORD_PROTOCOL_MAJ_VERSION_OFFSET] != TLS_MAJOR)
	{
	    printf("    ERR Invalid protocol version received in record header.\n");
	    goto end;
	}

	if(ssl_conn->record[TLS_RECORD_PROTOCOL_MIN_VERSION_OFFSET] == TLS_MINOR)
	{
	    ssl_conn->ssl_version = VERSION_TLS;
	}
	else if(ssl_conn->record[TLS_RECORD_PROTOCOL_MIN_VERSION_OFFSET] == SSL_MINOR)
	{
	    ssl_conn->ssl_version = VERSION_SSL3;
	}
	else
	{
	    printf("    ERR Invalid protocol version received in record header.\n");
	    goto end;
	}

	/* process it */
	ProcessTLSClientHello(ssl_conn->record + TLS_RECORD_HEADER_SIZE); 
    }

    /* flag it as having received a client hello */
    ssl_conn->recv_client_hello = 1;
    
    /* send the data over to the server, use bytes read as a return value */
    bytes_read = utlnet_WritenBytesToSocket(ssl_conn->server_fd,
					    ssl_conn->record, 
					    ssl_conn->record_len);
    
 end:
    return bytes_read;
}


/*
  Reads from the server socket and writes it to the client one. We
  need to flip some values to do the server read and then reset them
  when we are done.

  returns the return code from ClientRead.
*/
static int 
ServerRead(ssl_connection *ssl_conn)
{
    int return_val;

    /* set the appropriate read and write sockets */
    ssl_conn->read_fd = ssl_conn->server_fd;
    ssl_conn->write_fd = ssl_conn->client_fd;

    /* set the right change cipher */
    ssl_conn->recv_change = 
	&(ssl_conn->recv_change_cipher[SERVER_RECV_CHANGE_CIPHER]);
    
    /* leverage client read */
    return_val = ClientRead(ssl_conn);

    /* revert back to the default values */ 
    ssl_conn->recv_change = 
	&(ssl_conn->recv_change_cipher[CLIENT_RECV_CHANGE_CIPHER]); 
    ssl_conn->read_fd = ssl_conn->client_fd;
    ssl_conn->write_fd = ssl_conn->server_fd;       

    return return_val;
}

/*
  Called by DoOneSSLConnection to read from the client socket within the 
  select loop. Reads from the client socket and writes the data to the server
  socket.
  
  It reads sockets of up to any size using dynamically allocated memory. 
*/
static int
ClientRead(ssl_connection *ssl_conn)
{   	
    int bytes_read = 0;
    char buf[1];

    /* we process SSLV2 and TLS connections differently */
    if(ssl_conn->ssl_version != VERSION_SSL2)
    {
	/*
	  this catches the case where the client initially sends a V2 hello
	  with version 3 but the server can only do V2 and hence replies in
	  V2
	*/
	if(!ssl_conn->recv_server_hello)
	{
	    /* peek at the first byte to ensure that it's not a V2 server hello */
	    if(utlnet_PeekAtnBytesFromSocket(ssl_conn->read_fd, buf, 1) < 0)
	    {
		return -1;
	    }
	    if(buf[0] & 0x80)
	    {
		ssl_conn->ssl_version = VERSION_SSL2;
		return ClientRead(ssl_conn);
	    }
	}

	/* TLS connection */
	if((bytes_read = ReadOneTLSRecord(ssl_conn)) > 0)
	{
	    /* processes the packet */
	    ProcessTLSPacketType(ssl_conn);
	}
    }
    else
    {
	/* SSLV2 connection */
	if((bytes_read = ReadOneSSL2Record(ssl_conn)) > 0)
	{
	    ProcessOneSSL2Record(ssl_conn);
	}
    }
    
    /* sends it to the other end if there is something to send */
    if(bytes_read > 0)
    {
	bytes_read = utlnet_WriteToSocket(ssl_conn->write_fd, 
					  ssl_conn->record, 
					  ssl_conn->record_len);
    }
    
    if(ssl_conn->record_len != 0 && ssl_conn->record != NULL)
    {
	free(ssl_conn->record);
    }
   
    return bytes_read;
}


/*
  Called by ClientRead. Reads from the socket till one complete
  Record has been read in and then returns the buffer.
  
  returns the number of bytes read.
*/
static int
ReadOneTLSRecord(ssl_connection *ssl_conn)
{
    int bytes_read;
    char record_hdr_buf[TLS_RECORD_HEADER_SIZE];
    short record_len;
    
    ssl_conn->record_len = 0;
    ssl_conn->record = NULL;

    /* read in just the record header */
    if((bytes_read = utlnet_ReadnBytesFromSocket(ssl_conn->read_fd, 
						 record_hdr_buf,
						 TLS_RECORD_HEADER_SIZE)) <= 0)
    {
	return bytes_read;
    }
    
    /* find out how big this record is and allocate mem for it */
    record_len = TwoBytesToInt(&(record_hdr_buf[TLS_RECORD_LENGTH_OFFSET]));

    ssl_conn->record_len = (int) record_len + TLS_RECORD_HEADER_SIZE;

    return ReadRecordData(ssl_conn, record_hdr_buf, TLS_RECORD_HEADER_SIZE);
}

static int 
ReadOneSSL2Record(ssl_connection *ssl_conn)
{
    char record_hdr_buf[SSL2_2BYTE_RECORD_HEADER_SIZE];
    int bytes_read = 0;

    ssl_conn->record_len = 0;
    ssl_conn->record = NULL;

    /* read in the first two bytes and check how long the record is */
    if((bytes_read = utlnet_ReadnBytesFromSocket(ssl_conn->read_fd, 
						 record_hdr_buf,
						 SSL2_2BYTE_RECORD_HEADER_SIZE)) 
       <= 0)
    {
	return bytes_read;
    }

    /* check how long header length is */
    if(record_hdr_buf[0] & 0x80)
    {
	/* 2 bytes */
	ssl_conn->ssl2_record_hdr_len = SSL2_2BYTE_RECORD_HEADER_SIZE;
	ssl_conn->record_len = 
	    (((((unsigned int) record_hdr_buf[0]) & 0x7f) << 8) | 
	     ((unsigned char) record_hdr_buf[1]) )
	    + SSL2_2BYTE_RECORD_HEADER_SIZE;
    }
    else
    {
	/* 3 bytes */
	ssl_conn->ssl2_record_hdr_len = SSL2_3BYTE_RECORD_HEADER_SIZE;
	ssl_conn->record_len = 
	    ((((unsigned int) record_hdr_buf[0] & 0x3f) << 8) 
	     | ((unsigned char) record_hdr_buf[1]))
	    + SSL2_3BYTE_RECORD_HEADER_SIZE;     
    }

    /* read the rest of the record in */
    if((bytes_read = ReadRecordData(ssl_conn, 
				    record_hdr_buf,
				    SSL2_2BYTE_RECORD_HEADER_SIZE)) <= 0)
    {
	return bytes_read;
    }

    /* if it's padded, get the padding length */
    if(ssl_conn->ssl2_record_hdr_len == SSL2_3BYTE_RECORD_HEADER_SIZE)
    {
	ssl_conn->ssl2_padding_len = (unsigned char) ssl_conn->record[2];
    }

    return bytes_read;
}

/* 
   reads the rest of the record in. usually called after having read
   the record header in.

   the record len of the ssl_conn should be set to the total num of
   bytes to be read including the previously read bytes before calling
   this function.

   returns the number of bytes read.
*/
static int ReadRecordData(ssl_connection *ssl_conn, 
			  char *prev_read_buf, 
			  int num_prev_read_bytes)
{
    int bytes_read;

    ssl_conn->record = (char *) utl_GetMem(ssl_conn->record_len);
    
    /* copy the previous bytes over */
    memcpy(ssl_conn->record, prev_read_buf, num_prev_read_bytes);
    
    /* then read the rest of the buffer in */    
    if((bytes_read = 
	utlnet_ReadnBytesFromSocket(ssl_conn->read_fd, 
				    ssl_conn->record + num_prev_read_bytes, 
				    ssl_conn->record_len - num_prev_read_bytes)) 
       <= 0)
    {
	goto end;
    }
    
    return ssl_conn->record_len;

 end:
    free(ssl_conn->record); /* cannot be null */
    return bytes_read;
}


/* ------------------------ SSL3 / TLS ------------------------ */

/*
  Handles TLS packets that it reads from the socket. there might be
  more than one packet in the data that it reads and so it has to
  handle those cases. Also application data does not come in nice big
  packets and might be passed to the proxy in fragments and we handle
  that too.  Determines the kind of packet that has been sent. Handles
  TLS Record Headers.

  If the data is encrypted, then no further processing is done. This is 
  signalled by the recv_change_cipher argument

  returns the content type.
*/

static int
ProcessTLSPacketType(ssl_connection *ssl_conn)
{
    int i;
    char *rec_hdr = ssl_conn->record;
    char *c = (char *) rec_hdr;

    /* print out protocol version */
    printf("From Record Header -- Protocol Version: %d.%d\n",
	   rec_hdr[1], rec_hdr[2]);
    
    printf("                      Record Length: %d\n", 
	   ssl_conn->record_len - TLS_RECORD_HEADER_SIZE);
    
    switch( (unsigned int) rec_hdr[0])
    {
    case TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC:
	
	printf("Received a CHANGE_CIPHER_SPEC packet:\n"
	       "Further packets will be encrypted ... ");
	
	/* signals that no more processing is to be done */
	*(ssl_conn->recv_change) = (char) 1;
	break;
	
    case TLS_RECORD_TYPE_ALERT:
	
	printf("Received an ALERT packet ...\n");
	
	/* only process if we have not received the change cipher spec */
	if(!(*(ssl_conn->recv_change)))
	{
	    ProcessTLSAlertMessage(ssl_conn);
	}
	else
	{
	    printf("Packet is encrypted.");
	}
	break;
	
    case TLS_RECORD_TYPE_HANDSHAKE:
	
	printf("Received a HANDSHAKE packet ...\n");

	/* only process if we have not received the change cipher spec */
	if(!(*(ssl_conn->recv_change)))
	{
	    ProcessTLSHandshakeMessage(ssl_conn);	    
	}
	else
	{
	    printf("Packet is encrypted.");
	}
	break;
	
    case TLS_RECORD_TYPE_APPLICATION_DATA:
	
	printf("Received APPLICATION DATA packet ...\n");
	if(*(ssl_conn->recv_change))
	{
	    printf("Packet is encrypted.");
	}
	break;
	
    default:
	
	if(ssl_conn->recv_server_hello)
	{
	    printf("Received Unrecognised TLS packet, type %d\n",
		   rec_hdr[0]);
	    printf("First 30 bytes of data from packet\n");
	    for(i = 0; i < 30; i++, c++)
	    {
		printf("%d ",*c);
	    }
	    printf("\n\n");	
	}
	return -1;	
    }

    return rec_hdr[0];
}

/*
  Takes in an alert struct and prints out the level of the alert and also
  the description of the alert.
*/
static void 
ProcessTLSAlertMessage(ssl_connection *ssl_conn)
{
    char *str;
    char *alert_data = ssl_conn->record + TLS_RECORD_HEADER_SIZE;
    
    if( (unsigned int) alert_data[0] == TLS_ALERT_LEVEL_WARNING)
    {
	printf("Alert Level: Warning -- ");
    }
    else if( (unsigned int) alert_data[0] == TLS_ALERT_LEVEL_FATAL)
    {
	printf("Alert Level: Fatal -- ");
    }
    
    switch( (unsigned int) alert_data[1])
    {
    case TLS_ALERT_TYPE_CLOSE_NOTIFY:
	str = "CLOSE_NOTIFY\n"; 
	break;
    case TLS_ALERT_TYPE_UNEXPECTED_MESSAGE:
	str = "UNEXPECTED_MESSAGE\n"; 
	break;
    case TLS_ALERT_TYPE_BAD_RECORD_MAC:
	str = "BAD_RECORD_MAC\n"; 
	break;
    case TLS_ALERT_TYPE_DECRYPTION_FAILED:
	str = "DECRYPTION_FAILED\n"; 
	break;
    case TLS_ALERT_TYPE_RECORD_OVERFLOW:
	str = "RECORD_OVERFLOW\n"; 
	break;
    case TLS_ALERT_TYPE_DECOMPRESSION_FAILURE:
	str = "DECOMPRESSION_FAILURE\n"; 
	break;
    case TLS_ALERT_TYPE_HANDSHAKE_FAILURE:
	str = "HANDSHAKE_FAILURE\n"; 
	break;
    case TLS_ALERT_TYPE_BAD_CERTIFICATE:
	str = "BAD_CERTIFICATE\n"; 
	break;
    case TLS_ALERT_TYPE_UNSUPPORTED_CERTIFICATE:
	str = "UNSUPPORTED_CERTIFICATE\n"; 
	break;
    case TLS_ALERT_TYPE_CERTIFICATE_REVOKED:
	str = "CERTIFICATE_REVOKED\n"; 
	break;
    case TLS_ALERT_TYPE_CERTIFICATE_EXPIRED:
	str = "CERTIFICATE_EXPIRED\n"; 
	break;
    case TLS_ALERT_TYPE_CERTIFICATE_UNKNOWN:
	str = "CERTIFICATE_UNKNOWN\n"; 
	break;
    case TLS_ALERT_TYPE_ILLEGAL_PARAMETER:
	str = "ILLEGAL_PARAMETER\n"; 
	break;
    case TLS_ALERT_TYPE_UNKNOWN_CA:
	str = "UNKNOWN_CA\n"; 
	break;
    case TLS_ALERT_TYPE_ACCESS_DENIED:
	str = "ACCESS_DENIED\n"; 
	break;
    case TLS_ALERT_TYPE_DECODE_ERROR:
	str = "DECODE_ERROR\n"; 
	break;
    case TLS_ALERT_TYPE_DECRYPT_ERROR:
	str = "DECRYPT_ERROR\n"; 
	break;
    case TLS_ALERT_TYPE_EXPORT_RESTRICTION:
	str = "EXPORT_RESTRICTION\n"; 
	break;
    case TLS_ALERT_TYPE_PROTOCOL_VERSION:
	str = "PROTOCOL_VERSION\n"; 
	break;
    case TLS_ALERT_TYPE_INSUFFICIENT_SECURITY:
	str = "INSUFFICIENT_SECURITY\n"; 
	break;
    case TLS_ALERT_TYPE_INTERNAL_ERROR:
	str = "INTERNAL_ERROR\n"; 
	break;
    case TLS_ALERT_TYPE_USER_CANCELED:
	str = "USER_CANCELLED\n"; 
	break;
    case TLS_ALERT_TYPE_NO_RENEGOTIATION:
	str = "NO_RENEGOTIATION\n"; 
	break;
    default:
	printf("No such alert code %d\n", (unsigned int) alert_data[1]);
	return;
    }
    printf("%s\n",str);
}

/*
  Pass in the data segment containing the handshake data extracted from
  the TLS Record. Determines the type and takes the appropriate action.
  Mostly just prints out the Handshake request.
*/
static void
ProcessTLSHandshakeMessage(ssl_connection *ssl_conn)
{
    char *cur_handshake_packet;
    int bytes_processed = 0;
    int total_bytes_to_process = ssl_conn->record_len - TLS_RECORD_HEADER_SIZE;
    int handshake_packet_len;

    /* move to the first record */
    cur_handshake_packet = ssl_conn->record + TLS_RECORD_HEADER_SIZE;

    /* 
       want to keep looping till we've processed all the handshake packets
       in a single record. this deals with the multiple handshake packets
       in one single record 
    */
    while(bytes_processed < total_bytes_to_process)
    {	
	/* process the current handshake packet */
	printf("HandShake Packet Type :- ");
	
	switch(cur_handshake_packet[0])
	{
	case TLS_HANDSHAKE_TYPE_HELLO_REQUEST:

	    printf("Hello Request\n");
	    break;

	case TLS_HANDSHAKE_TYPE_CLIENT_HELLO:

	    printf("SSLV3/TLS Client Hello\n");
	    ProcessTLSClientHello(cur_handshake_packet);
	    break;

	case TLS_HANDSHAKE_TYPE_SERVER_HELLO:

	    printf("Server Hello\n");
	    ProcessServerHello(cur_handshake_packet, ssl_conn);
	    ssl_conn->recv_server_hello = 1;
	    break;

	case TLS_HANDSHAKE_TYPE_CERTIFICATE:

	    printf("Certificate\n");
	    ProcessCertificateChain(cur_handshake_packet, ssl_conn);
	    break;

	case TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:

	    printf("Server Key Exchange\n");
	    ProcessTLSServerKeyExchange(cur_handshake_packet, ssl_conn);	   
	    break;

	case TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST:

	    printf("Certificate request\n");
	    ProcessCertificateRequest(cur_handshake_packet, ssl_conn);
	    break;

	case TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE:

	    printf("Server hello done\n");
	    break;

	case TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY:

	    printf("Certificate verify\n");
	    break;

	case TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:

	    printf("Client key exchange\n");
	    ProcessTLSClientKeyExchange(cur_handshake_packet, ssl_conn);
	    break;

	case TLS_HANDSHAKE_TYPE_FINISHED:

	    printf("Finished Handshake!\n");
	    break;

	default:
	    printf("Can't recognise Handshake request type %d!\n",cur_handshake_packet[0]);
	}
	
	/* 
	   pull out the content length of the handshake packet and add it to
	   both the bytes processed and also the currentpacket pointer 
	*/
	handshake_packet_len = ThreeBytesToInt(&(cur_handshake_packet[1]));
	bytes_processed += handshake_packet_len + TLS_HANDSHAKE_HEADER_SIZE;
	cur_handshake_packet += handshake_packet_len + TLS_HANDSHAKE_HEADER_SIZE;

	/* just for formatting reasons */ 
	if(bytes_processed < total_bytes_to_process)
	{
	    printf("\n");
	}
    }
}

/*
  Given the handshake packet containing the Client Hello message, this
  processes it to obtain the protocol version, session ID and the list of 
  cipher suite that the client can use.
*/
static void 
ProcessTLSClientHello(char *buffer)
{
    char *ptr; /* points at cipher suite */
    short cipher_suite_len;
    int i;
    
    printf("From Client Hello -- ");
    ptr = ProcessTLSHello(buffer);

    memcpy(&cipher_suite_len, ptr, 2);
    cipher_suite_len = ntohs(cipher_suite_len);
    printf("Cipher suite length is %d bytes ... number of cipher suites %d\n",
	   cipher_suite_len,cipher_suite_len / 2);
    
    ptr += 2; /* advance over the length field of cipher suite */
    
    printf("List of cipher suites are -- \n");
    for(i = 0; i < cipher_suite_len; i += 2)    
        ProcessTLSCipherSuite(ptr[i], ptr[i + 1]);
    
}

/*
  Given the handshake packet containing either the ClientHello or ServerHello
  message, it extracts the protocol version, the session ID which is 
  printed byte by byte in hex and returns the a pointer to the length field 
  of the cipher suite.
*/
static char *
ProcessTLSHello(char *buffer)
{
    char *temp, *ptr = buffer + TLS_HANDSHAKE_HEADER_SIZE;
    int i;
    unsigned int byte;
    
    /* print out protocol version */
    printf("Protocol Version %d.%d\n",(int)ptr[0],(int)ptr[1]);
    
    ptr += SESSION_ID_OFFSET; /* skip over random and protocol version field */
    
    /* 
       sesssion ID in a hello record is only max 32 bytes => need 1
       byte session ID
    */
    printf("Length of session ID -- %d bytes\n",(int) (*ptr));
    
    /* 
       nothing big enough to hold a number of 32 bytes so just iterate
       over the chars and print them
    */
    printf("Session ID --\n  0x");
    
    for(i = 0, temp = ptr + 1; i < *ptr; i++, temp++)
    {
	byte = 0;
	memcpy(&byte, temp, 1);
	printf("%2.2x",byte);
    }
    printf("\n");
  
    /* skip over the number of bytes in the session ID field */
    ptr += ((*ptr) + 1); /* now pointing at cipher suite */
    
    return ptr;
}

/*
  Given the handshake packet containing the Server Hello message, this
  processes it to obtain the protocol version, session ID and the
  cipher suite that is to be used.
*/
static void
ProcessServerHello(char *buffer, ssl_connection *ssl_conn)
{
    char *ptr;

    printf("From Server Hello -- ");
    ptr = ProcessTLSHello(buffer); /* points at cipher suite */
    printf("Cipher Suite is -- \n");
    ProcessTLSCipherSuite(ptr[0], ptr[1]);
    
    DetermineTLSKeyExchangeAlgorithm(ptr[1], ssl_conn);
}

/*
  Examines the bytes given and prints out the cipher suite that is
  being used.
*/
static void
ProcessTLSCipherSuite(char byte1,char byte2)
{
    char *name;
    
    if(byte1 == (char)0xff)
    {
	printf("  Hex Code:");
	utl_PrintCharAsHex(byte1);
	utl_PrintCharAsHex(byte2);
	printf("\n  Type: Unknown Cipher Suite\n");
	return;
    }
    
    /* done because 0x will only be prefixed to a non zero result. */
    printf("  Hex Code:");
    utl_PrintCharAsHex(byte1);
    utl_PrintCharAsHex(byte2);
    printf("\n  Type: ");
    
    switch(byte2)
    {
    case 0x00: 
	name = "No encryption"; 
	break;
    case 0x01: 
	name = "RSA with hash function MD5"; 
	break;
    case 0x02: 
	name = "RSA with SHA"; 
	break;
    case 0x03: 
	name = "RSA EXPORT with 40 bit RC4 and hash function MD5";
	break;
    case 0x04: 
	name = "RSA with 128 bit RC4 and hash function MD5";
	break;
    case 0x05: 
	name = "RSA with 128 bit RC4 and hash function SHA";
	break;
    case 0x06: 
	name = "RSA EXPORT with 40 bit RC2 in CBC mode and hash function MD5"; 
	break;
    case 0x07: 
	name = "RSA with IDEA in CBC mode and hash function SHA";
	break;
    case 0x08:
	name = "RSA EXPORT with 40 bit DES in CBC mode and hash function SHA"; 
	break;
    case 0x09:
	name = "RSA with DES in CBC mode and hash function SHA";
	break;
    case 0x0A:
	name = "RSA with 3DES EDE in CBC mode and hash function SHA";
	break;
    case 0x0B:
	name = "DH DSS EXPORT with 40 bit DES in CBC mode and hash function SHA";
	break;
    case 0x0C:
	name = "DH DSS with DES in CBC mode and hash function SHA";
	break;
    case 0x0D:
	name = "DH DSS with 3DES EDE in CBC mode and hash function SHA";
	break;
    case 0x0E: 
	name = "DH RSA EXPORT with 40 bit DES in CBC mode and hash function SHA";
	break;
    case 0x0F:
	name = "DH RSA with DES in CBC mode and hash function SHA";
	break;
    case 0x10:
	name = "DH RSA with 3DES EDE in CBC mode and hash function SHA";
	break;
    case 0x11: 
	name = "DHE DSS EXPORT with 40 bit DES in CBC mode and hash function SHA";
	break;
    case 0x12:
	name = "DHE DSS with DES in CBC mode and hash function SHA";
	break;
    case 0x13:
	name = "DHE DSS with 3DES EDE in CBC mode and hash function SHA";
	break;
    case 0x14:
	name = "RSA EXPORT with 40 bit DES in CBC mode and hash function SHA";
	break;
    case 0x15:
	name = "DHE RSA with DES in CBC mode and hash function SHA";
	break;
    case 0x16:
	name = "DHE RSA with 3DES EDE in CBC mode and hash function SHA";
	break;
    case 0x17:
	name = "Anonymous DH EXPORT with 40 bit RC4 and hash function MD5";
	break;
    case 0x18:
	name = "Anonymous DH with 128 bit RC4 and hash function MD5";
	break;
    case 0x19:
	name = "Anonymous DH EXPORT with 40 bit DES in CBC mode and hash function SHA"; 
	break;
    case 0x1A:
	name = "Anonymous DH with DES in CBC mode and hash function SHA";
	break;
    case 0x1B:
	name = "Anonymous DH with 3DES EDE in CBC mode and hash function SHA"; 
	break;

	/* Elliptic Curve Cipher Suites */

    case 0x34:
	name = "Elliptic Curve DHE DSS and hash function SHA";
	break;
    case 0x36:
	name = "Elliptic Curve DHE DSS with 128 bit RC4 and hash function SHA";
	break;
    case 0x37:
	name = "Elliptic Curve DHE DSS with DES CBC and hash function SHA";
	break;
    case 0x38:
	name = "Elliptic Curve DHE DSS with 3DES EDE CBC and hash function SHA";
	break;
    case 0x39:
	name = "Elliptic Curve DHE DSS Export with 40 bit DES CBC and hash function SHA";
	break;
    case 0x40:
	name = "Elliptic Curve DHE DSS Export with 40 bit RC4 and hash function SHA";
	break;
    case 0x60:
	name = "RSA Export with 56 bit RC4 and hash function MD5";
	break;
    case 0x61:
	name = "RSA Export with 56 bit RC2 CBC and hash function MD5";
	break;
    case 0x62:
	name = "RSA Export with DES CBC and hash function SHA";
	break;
    case 0x63:
	name = "DHE DSS Export with DES CBC and hash function SHA";
      break;
    case 0x64:
	name = "RSA Export with 56 bit RC4 and hash function SHA";
	break;
    case 0x65:
	name = "DHE DSS Export with 56 bit RC4 and hash function SHA";
	break;
    case 0x66:
	name = "DHE DSS with 128 bit RC4 and hash function SHA";
	break;
    default: 
	printf("Unknown Cipher Suite\n"); 
	return;
    }
    printf("%s\n",name);    
}

/*
  Determines if the algorithm is using DH or RSA and returns the value
  through keyxchange_alg field of the ssl_conn struct.
*/
static void
DetermineTLSKeyExchangeAlgorithm(char byte1, ssl_connection *ssl_conn)
{
  switch(byte1)
    {
    case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: 
    case 0x07: case 0x08: case 0x09: case 0x0A: case 0x14:
    case 0x60: case 0x61: case 0x62: case 0x64:
       ssl_conn->keyxchange_alg = RSA; break;
    case 0x0B: case 0x0C: case 0x0D: case 0x0E: case 0x0F: case 0x10:
    case 0x11: case 0x12: case 0x13:
    case 0x15: case 0x16: case 0x17: case 0x18: case 0x19: case 0x1A:
    case 0x1B:
    case 0x34: case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
    case 0x40:
    case 0x63: case 0x65: case 0x66:
      ssl_conn->keyxchange_alg = DH; break; 
    default:
      printf("Error: no such key exchange algorithm\n");
    }
}


/*
  processes the certificates that the server might send to the client.
  uses code from the openssl library.

  This should not be used for a SSLV2 certificate data because it
  seems like V2 does not support cert chains.
*/
static void
ProcessCertificateChain(char *buffer, ssl_connection *ssl_conn)
{
    X509 *cert = NULL;
    unsigned long nc, llen, l;
    unsigned char *p,*d,*q;   

    /* from openssl, including naming conventions */

    /* these pointers are different depending on what version of ssl */
    if(ssl_conn->ssl_version == VERSION_TLS || 
       ssl_conn->ssl_version == VERSION_SSL3)
    {
	d = p = (unsigned char *) (buffer + TLS_HANDSHAKE_HEADER_SIZE);
    }
    else
    {
	printf("    ERR Incorrect SSL version in record header for certificate.\n");
        return;
    }

    n2l3(p, llen);
    
    for (nc = 0; nc < llen; )
    {
	n2l3(p, l);

	if ((l + nc + 3) > llen)
	{
	    printf("    ERR Certificate length mismatch\n"); 
	    return;
	}
	
	q = p;
	
	cert = d2i_X509(NULL, &q, l); /* grab the current cert */
	
	if (cert == NULL)
	{
	    printf("    ERR Bad Certificate\n"); 
	    return;
	}
	if (q != (p + l))
	{
	    printf("    ERR in Certificate Decode\n"); 
	    return;
	}
	
	ProcessCertificate(cert);
	
	cert = NULL;
	nc += l + 3;
	p = q;
    }
}

/*
  takes the X509 certificate and parses out the information into a
  UTL_CERT_INFO struct. Taken from Dan Boneh's utl_cert.c
*/
static void
ProcessCertificate(X509 *x)
{
    UTL_CERT_INFO buf;
    BIO *mem = NULL;
    EVP_PKEY *key;
    
    #if 0
    if ((mem=BIO_new(BIO_s_mem())) == NULL)
    {
	printf("ERR Unable to create new BIO\n");
	return;
    }
    
    /* Extract and process validity periods */
    ASN1_UTCTIME_print(mem, X509_get_notAfter(x));
    BIO_gets(mem, buf.notAfter, sizeof(buf.notAfter));
    ASN1_UTCTIME_print(mem, X509_get_notBefore(x));
    BIO_gets(mem, buf.notBefore, sizeof(buf.notBefore));
    
    /* Extract and process subject name */
    buf.subj = X509_get_subject_name(x);
    X509_NAME_oneline(buf.subj,
		      buf.subj_DistName, sizeof(buf.subj_DistName) );
    
    /* Extract and process issuer name */
    buf.issuer = X509_get_issuer_name(x);
    X509_NAME_oneline(buf.issuer,
		      buf.issuer_DistName, sizeof(buf.issuer_DistName) );
    
    /* get the key size */
    key = X509_get_pubkey(x);
    
    //PrintCertificateInfo(&buf,key);
    
    BIO_free(mem);
    EVP_PKEY_free(key);
    #endif
}

#if 0
/*
  takes the info from utl_cert_info and prints out the info. 
  also prints out the key size and type of key exchange mechanism.
  key handling taken from Dan Boneh's utl_cert.c
*/
static void
PrintCertificateInfo(UTL_CERT_INFO *buf, EVP_PKEY *key)
{
    printf("  CERTIFICATE INFORMATION :- \n");
    printf("  Validity -- Not After  %s\n",buf->notAfter);
    printf("              Not Before %s\n",buf->notBefore);
    printf("  Subject Distinguished Name -- \n    %s\n",buf->subj_DistName);
    printf("  Issuer Distinguished Name  -- \n    %s\n",buf->issuer_DistName);
    
    if (key == NULL) return;
    
    switch (key->type) 
    {
    case EVP_PKEY_RSA:
	buf->keysize = RSA_size(key->pkey.rsa)*8;
	printf("  RSA Public key size %d bits\n\n",buf->keysize);
	break;      
    case EVP_PKEY_DSA:
	buf->keysize = DSA_size(key->pkey.dsa)*8;
	printf("  DSS Public key size %d bits\n\n",buf->keysize);
	break;
    default:
	printf("  Unknown key type\n\n");
    }
}
#endif

/*
  prints out the types of certificates requested. At present just
  dumps out the distinguished names of the CA as a string.
*/
static void 
ProcessCertificateRequest(char *buffer, ssl_connection *ssl_conn)
{
    char *data = buffer + TLS_HANDSHAKE_HEADER_SIZE;
    char *temp;
    unsigned int cert_type_len = 0;
    int i;  
    unsigned int len = ThreeBytesToInt(buffer + 1);

    printf("Types of certificates requested --\n");
    memcpy(&cert_type_len, data, 1);
    
    for(i = 0, data++; i < cert_type_len; i++, data++)
    {
        switch(*data)
	{
	case 1:
	    printf("\tRSA certificate\n"); 
	    break;	  
	case 2:
	    printf("\tDSS certificate\n"); 
	    break;
	case 3:
	    printf("\tRSA certificate with fixed DH parameters\n"); 
	    break;
	case 4:
	    printf("\tDSS certificate with fixed DH parameters\n"); 
	    break;
	default:
	    printf("\tUnknown certificate requested\n"); 
	    break;
	}
    }
  
    /* print out the distinguished names of the CA */
    len -= cert_type_len;
    temp = (char *) utl_GetMem(len + 1);
    memcpy(temp, data, len);
    temp[len] = '\0';
    printf("Distinguished Names of CA's -- %s", temp);
    
    free(temp);  
}

/*
  processes the server key exchange to obtain the parameters. 
  depending on whether the algorithm is RSA or DSS, different
  params will be printed out.
*/
static void 
ProcessTLSServerKeyExchange(char *buffer, ssl_connection *ssl_conn)
{
    char *data = buffer + TLS_HANDSHAKE_HEADER_SIZE;

    switch(ssl_conn->keyxchange_alg)
    {
    case RSA:
	data = ExtractParams(data, "RSA Modulus");
	ExtractParams(data, "RSA Exponent");
	break;
    case DH:
	data = ExtractParams(data, "DH Prime Modulus p");
	data = ExtractParams(data, "DH Generator g");
	data = ExtractParams(data, "DH public value (g^X mod p)");
	break;
    }
}

/*
  prints out the data in hex of the parameters. assumes that the length
  of the data is given by the first 2 bytes.
*/
static char *
ExtractParams(char *params, char *type)
{
    unsigned short param_len = TwoBytesToInt(params);
    char *start = params;
    int i;  
    unsigned int byte;
    
    printf("Length of %s -- %d\n", type, param_len);
    printf("%s --\n  0x",type);

    /* skip over two byte length field */
    for(i = 0, params += 2; i < param_len; i++, params++)
    {
	byte = 0; memcpy(&byte, params, 1);
	printf("%2.2x", byte);		
    }
    printf("\n"); 
    return (start + 2 + param_len);
}

/*
  Using the keyxchange_alg field of the ssl_conn passed in, will
  process and print out the appropriate information. For RSA, prints
  out the RSA encrypted premaster secret and for DH, prints out the
  public value.
*/
static void 
ProcessTLSClientKeyExchange(char *buffer, ssl_connection *ssl_conn)
{
    char *ptr = buffer + TLS_HANDSHAKE_HEADER_SIZE;
    int i; 
    unsigned int len = ThreeBytesToInt(buffer+1);
    unsigned int byte = 0;  
    
    switch(ssl_conn->keyxchange_alg)
    {
    case RSA:

        printf("Length of RSA Encrypted PreMaster Secret -- %d bytes\n",len);      
	printf("RSA Encrypted PreMaster Secret --\n  0x");

	/* 1 for first byte specifying type and 3 for length field */
	for(i = 0, ptr += 4; i < len; i++, ptr++)
	{
	    byte = 0; memcpy(&byte, ptr, 1);
	    printf("%2.2x", byte);		
	}
	printf("\n");
	break;
    case DH:
        if(!len)
	{
	    ExtractParams(ptr,"DH public value");
	}
	else
	{
	    printf("DH public key is implicit in client certificate\n");
	}
	break;
    default:
        printf("Unable to process Client Key Exchange %d\n", ssl_conn->keyxchange_alg);
    }
}


/* ---------------------------- SSL2 -------------------------------- */


static int 
ProcessOneSSL2Record(ssl_connection *ssl_conn)
{
    /* print out protocol version */
    printf("Protocol Version: SSLV2\n");
    printf("From Record Header -- Record Length: %d\n", 
	   ssl_conn->record_len - ssl_conn->ssl2_record_hdr_len );

    /* print out padding length if record was padded */
    if(ssl_conn->ssl2_record_hdr_len == SSL2_3BYTE_RECORD_HEADER_SIZE)
    {
	printf("                      Padding Length: %d\n",
	       ssl_conn->ssl2_padding_len);
    }

    /* 
       the packet is encrypted. we cannot even parse to determine the
       content type 
    */
    if(ssl_conn->ssl2_packets_encrypted)
    {
	printf("Packet is encrypted.\n");
	return 1;
    }

    switch(ssl_conn->record[ssl_conn->ssl2_record_hdr_len])
    {
    case SSL2_MT_CLIENT_MASTER_KEY:

	ProcessSSLV2ClientMasterKey(ssl_conn);
	
	/* all further packets will be encrypted */
	ssl_conn->ssl2_packets_encrypted = 1;

	break;

    case SSL2_MT_CLIENT_HELLO:

	/* this should never be called though */
	ProcessSSLV2ClientHello(ssl_conn);
	break;  

    case SSL2_MT_SERVER_HELLO:
       
        /* 
	   check if we should expect a client master key packet next by
	   looking at the resume hit char
	*/
	if(ssl_conn->record[ssl_conn->ssl2_record_hdr_len + 1] != 0)
	{
      	    /* since the session id hit, all further packets will be encrypted */
            ssl_conn->ssl2_packets_encrypted = 1;
	}
	ProcessSSLV2ServerHello(ssl_conn);
	break;

    case SSL2_MT_ERROR:

        ProcessSSLV2Error(ssl_conn);
	break;
/*
  these are all sent encrypted. since we are only parsing in this
  version, we cannot do anything since we don't even know the kind of
  packet this is

    case SSL2_MT_CLIENT_FINISHED:

        ProcessSSLV2ClientFinished(ssl_conn);
	break;

    case SSL2_MT_SERVER_VERIFY:

	break;
    case SSL2_MT_SERVER_FINISHED:

	break;
    case SSL2_MT_REQUEST_CERTIFICATE:

	break;
    case SSL2_MT_CLIENT_CERTIFICATE:

        ProcessSSLV2ClientCertificate(ssl_conn);
	break;
*/
    default:
        printf("Received Unknown packet type.\n");
	return -1;
    }
    
    //printf("\n");
    return 1;
}

/* 
    Processes the client master key packet.
*/
static void
ProcessSSLV2ClientMasterKey(ssl_connection *ssl_conn)
{
    unsigned short clear_key_data_len = 0;
    unsigned short encrypted_key_data_len = 0;
    unsigned short key_arg_data_len = 0;
    char *record = ssl_conn->record;

    printf("Received Client Master Key Packet --\n");
    printf("Cipher Suite --\n");
    
    ProcessSSLV2OneCipherSuite(record[1], record[2], record[3]);

    clear_key_data_len = 
	(((unsigned short) record[4]) << 8) | ((unsigned char) record[5]);
    encrypted_key_data_len = 
	(((unsigned short) record[6]) << 8) | ((unsigned char) record[7]);
    key_arg_data_len = 
	(((unsigned short) record[8]) << 8) | ((unsigned char) record[9]);

    printf("Clear Key Data Length     -- %hu\n", clear_key_data_len);
    printf("Encrypted Key Data Length -- %hu\n", encrypted_key_data_len);
    printf("Key Arg Data Length -- %hu\n", encrypted_key_data_len);
    printf("All further packets will be encrypted.\n");
}

/*
  Examines the bytes given and prints out the cipher suite that is being 
  used. This is used when a SSLV2 client hello is being processed.
*/
static void
ProcessSSLV2OneCipherSuite(char byte1, char byte2, char byte3)
{
    char unknown = 0;

    if(byte1 == 0x00) /* TLS Ciphers used */
    {
	ProcessTLSCipherSuite(byte2,byte3);
	return;
    }
    
    printf("  Hex Code:");
    utl_PrintCharAsHex(byte1);
    utl_PrintCharAsHex(byte2);
    utl_PrintCharAsHex(byte3);
    printf("\n  Type: ");
    
    switch((unsigned char) byte1)
    {      
    case 0x01:
	if(byte3 == (char) 0x80)
	{
	    printf("RSA with 128 bit RC4 and hash function MD5\n");
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x02:
	if(byte3 == (char) 0x80)
	{
	    printf("RSA Export with 40 bit RC4 and hash function MD5\n");
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x03:
	if(byte3 == (char) 0x80)
	{
	    printf("RSA with 128 bit RC2 CBC and hash function MD5\n");
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x04:
	if(byte3 == (char) 0x80)
	{
	    printf("RSA Export with 40 bit RC2 and hash function MD5\n");
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x05:
	if(byte3 == (char) 0x80)
	{
	    if(byte2 == (char) 0x00)
	    {
		printf("RSA with 128 bit IDEA CBC and hash function MD5\n");
	    }
	    else
	    {
		printf("RSA with 128 bit IDEA CBC and hash function SHA\n");
	    }
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x06:
	if(byte3 == (char) 0x40)
	{
	    printf("RSA with 64 bit DES CBC and hash function MD5\n");
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0x07:
	if(byte3 == (char) 0xC0)
	{
	    if(byte2 == (char) 0x00)
	    {
		printf("RSA with 192 bit 3DES EDE CBC and hash function MD5\n");
	    }
	    else
	    {
		printf("RSA with 192 bit 3DES EDE CBC and hash function SHA\n");
	    }
	}
	else 
	{
	    unknown = 1; 
	}
	break;
    case 0xff:
	if(byte3 == 0x00)
	{
	    printf("RSA with 64 bit DES CFB with hash function MD5\n");
	}
	else
	{
	    printf("No Cipher Suite\n");
	}
	break;
    default:
	unknown = 1;
    }
    
    if(unknown)
    {
	printf("Unknown SSLV2 cipher used\n");
    }
}

/*
  Processes the SSLV2 Client Hello message. This message is only sent by
  clients that support both TLS1.0 and SSLV2. Appendix E RFC 2246.
  
  Assumes that the buffer points to the record type which is 2 bytes
  after the start of the packet. -- not any more.
  Now assumes starts at record beginning.
*/
static void 
ProcessSSLV2ClientHello(ssl_connection *ssl_conn)
{   
    char *buffer = 
	    ssl_conn->record + SSL2_2BYTE_RECORD_HEADER_SIZE; /* skip over record */
    short cipher_spec_len = 
	    TwoBytesToInt(&(buffer[SSL2_CLIENT_HELLO_CIPHER_SPEC_LEN_OFFSET]));
    short session_id_len = 
	    TwoBytesToInt(&(buffer[SSL2_CLIENT_HELLO_SESSION_ID_LEN_OFFSET]));
    short challenge_len = 
	    TwoBytesToInt(&(buffer[SSL2_CLIENT_HELLO_CHALLENGE_LEN_OFFSET]));
    char *ptr;
    int session_id_offset = 
	    cipher_spec_len + SSL2_CLIENT_HELLO_CIPHER_SPEC_OFFSET;
    int i;
    unsigned int byte;

    printf("Received SSLV2 Client Hello ...\n");
    printf("\nFrom Client Hello -- Protocol Version: %d.%d\n",
	   buffer[1], buffer[2]);
    
    printf("Session ID Length -- %hd bytes\n", session_id_len);
    printf("Session ID --\n");
    for(i = 0, ptr = buffer + session_id_offset; 
	i < session_id_len; 
	i++, ptr++)
    {
	byte = 0;
	memcpy(&byte, ptr, 1);
	printf("%.2x", byte);
    }
    
    ProcessSSLV2CipherSuiteData(buffer + SSL2_CLIENT_HELLO_CIPHER_SPEC_OFFSET,
				cipher_spec_len);

    printf("Challenge Length -- %hd bytes\n", challenge_len);
}

/*
  Processes all the cipher suite data
*/
static void 
ProcessSSLV2CipherSuiteData(char *cipher_suite_data, 
			    unsigned short data_len)
{
    int i;
    char *ptr;

    printf("Cipher Suite Length %hd bytes ... number of cipher suites %d\n",
	   data_len, data_len / SSL2_ONE_CIPHER_SUITE_LEN);
    printf("Cipher Suite List is -- \n");
    for(i = 0, ptr = cipher_suite_data; 
	i < data_len; 
	i += SSL2_ONE_CIPHER_SUITE_LEN, ptr += SSL2_ONE_CIPHER_SUITE_LEN)
    {
	ProcessSSLV2OneCipherSuite(ptr[0], ptr[1], ptr[2]);      
    }
}

/* 
   Checks if the record hdr is a v2 client hello.  we don't have to
   worry about the padding byte because a client hello is always in
   plain text.
*/
static int
IsV2ClientHello(char *record_hdr)
{
    return((record_hdr[0] & 0x80) && 
	   (record_hdr[SSL2_MSG_TYPE_OFFSET] == SSL2_MT_CLIENT_HELLO));              
}

/* 
   prints out the relevant information for a server hello
*/
static void 
ProcessSSLV2ServerHello(ssl_connection *ssl_conn)
{
    char session_id_hit = 0;
    char certificate_type;
    unsigned short server_version;
    unsigned short certificate_len;
    unsigned short cipher_spec_len;
    unsigned short connection_id_len;
    char *record_data = ssl_conn->record + ssl_conn->ssl2_record_hdr_len;
    char *cert_data = record_data + SSL2_SERVER_HELLO_CERT_DATA_OFFSET;
    char *cipher_spec_data;

    X509 *cert;

    printf("Received Server Hello Packet --\n");   

    /* first pull out all the data */
    session_id_hit = record_data[1];
    certificate_type = record_data[2];
    server_version = ((unsigned short) (record_data[3] << 8)) | 
 	             ((unsigned char) record_data[4]);
    certificate_len = ((unsigned short) (record_data[5] << 8)) | 
	              ((unsigned char) record_data[6]);
    cipher_spec_len = ((unsigned short) (record_data[7] << 8)) | 
	              ((unsigned char) record_data[8]);
    connection_id_len = ((unsigned short) (record_data[9] << 8)) | 
	                ((unsigned char) record_data[10]);

    cipher_spec_data = cert_data + certificate_len;

    printf("Server version is %hu\n", server_version);    

    if(session_id_hit)
    {
        printf("Session ID matched previous session - SSL2 Resume\n"
	       "All further packets will be encrypted\n");
	return; /* all the other fields will be empty */
    }
    else
    {
        printf("Session ID did not match any previous session - No Resume\n");
    }
    
    /* 
       it appears that V2 doesn't seem to support the chain the same way 
       as TLS. In fact, it doesn't seem to support any chains at all.
       ProcessCertificateChain(cert_data, ssl_conn);
    */

    /* extract and print out the cert */
    cert = d2i_X509(NULL, (unsigned char **) &cert_data, certificate_len);
    ProcessCertificate(cert);

    ProcessSSLV2CipherSuiteData(cipher_spec_data, cipher_spec_len);

    printf("Connection ID len is %hu\n", connection_id_len);    
}

/* 
   prints out the relevant information for a server hello
*/
static void 
ProcessSSLV2Error(ssl_connection *ssl_conn)
{
    char *record_data = ssl_conn->record + ssl_conn->ssl2_record_hdr_len;
    unsigned short error_code;


    printf("Received SSLV2 Error -- \n");	   

    error_code = (record_data[1] << 8) | ((unsigned char) record_data[2]);

    printf("Error Code is %hu -- ", error_code);

    switch(error_code)
    {
    case SSL2_PE_NO_CIPHER:

        printf("No common ciphers supported.\n");
	break;

    case SSL2_PE_NO_CERTIFICATE:

        printf("No certificate sent by client.\n");
	break;

    case SSL2_PE_BAD_CERTIFICATE:

        printf("Bad certificate sent.\n");
	break;	    

    case SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE:

        printf("Unsupported certificate type.\n");
	break;	    

    default:

        printf("Unknown error.\n");
	break;	    	    
    }
}

#if 0
/*
    Since we are only parsing it and it is sent encrypted, we can't do
    very much here
*/
static void
ProcessSSLV2ClientFinished(ssl_connection *ssl_conn)
{
    printf("Received SSLV2 Client Finished -- \n"
	   "Packet is encrypted\n");
}

/*
    Since we are only parsing it and it is sent encrypted, we can't do
    very much here
*/
static void
ProcessSSLV2ClientCertificate(ssl_connection *ssl_conn)
{
    printf("Received SSLV2 Client Certificate --\n"
	   "Packet is encrypted\n\n");
}
#endif

/* --------------------- UTILITIES ---------------------------------- */


/*
  A wrapper for close that does some error checking.
*/
void 
CloseSocket(int sock)
{
  if(close(sock) < 0 )
    {      
      perror("Close socket error");
      exit(FAILURE);
    }
}

/*
  used for converting the short in 2 byte length fields to an
  int. returns the value as a short in the host byte order.

  can't dereference a short directly because it might not be word
  aligned.
*/
short
TwoBytesToInt(char *buffer)
{
    int i;  
    char *temp;
    short len = 0;
    
    /* get the length of the message */
    temp = (char *) &len;
    for(i = 0; i < 2; i++) /* 2 is the size of the length field */
    {
	memcpy(&(temp[i]), buffer + i, 1);
    }
    
    return ntohs(len);
}

/*
  used for converting the 3 byte field in the handshake packet that
  represents the length of the packet to an int
*/
unsigned int
ThreeBytesToInt(char *buffer)
{
    int i;  
    char *temp;
    unsigned int len = 0;
    
    /* get the length of the message */
    temp = (char *) &len;
    for(i = 0; i < 3; i++) /* 3 is the size of the length field */
    {
	memcpy(&(temp[i]), buffer + 2 - i, 1);
    }
    
    return len;
}
