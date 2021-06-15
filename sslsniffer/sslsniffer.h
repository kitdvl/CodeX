/*
  SSL Sniffer V1.21.
  ----------------------------------------------
  Written by: Eu-Jin Goh (eujin@cs.stanford.edu)
              Stanford University October 2000

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

#ifndef SSLSNIFFER_H
#define SSLSNIFFER_H

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define SUCCESS                                    0
#define FAILURE                                    1

/* command line flags */
#define SNIFFER_ARGV_PORT                          "-p"
#define SNIFFER_ARGV_NO_PROXY                      "-np"

/* default port that the sniffer listens on if no port is given */
#define DEFAULT_PORT                               8888

#define BUFFER_SIZE                                2048

/* Protocol Versions */
#define TLS_MAJOR                                  3
#define TLS_MINOR                                  1
#define SSL_MAJOR                                  3
#define SSL_MINOR                                  0

/* ------------------------- TLS -------------------------  */

/* Content Types */
#define TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC         20
#define TLS_RECORD_TYPE_ALERT                      21
#define TLS_RECORD_TYPE_HANDSHAKE                  22
#define TLS_RECORD_TYPE_APPLICATION_DATA           23
    
/* TLS Alert Protocol msg types */
#define TLS_ALERT_LEVEL_WARNING                    1
#define TLS_ALERT_LEVEL_FATAL                      2
#define TLS_ALERT_TYPE_CLOSE_NOTIFY                0
#define TLS_ALERT_TYPE_UNEXPECTED_MESSAGE          10
#define TLS_ALERT_TYPE_BAD_RECORD_MAC              20
#define TLS_ALERT_TYPE_DECRYPTION_FAILED           21
#define TLS_ALERT_TYPE_RECORD_OVERFLOW             22
#define TLS_ALERT_TYPE_DECOMPRESSION_FAILURE       30
#define TLS_ALERT_TYPE_HANDSHAKE_FAILURE           40
#define TLS_ALERT_TYPE_BAD_CERTIFICATE             42
#define TLS_ALERT_TYPE_UNSUPPORTED_CERTIFICATE     43
#define TLS_ALERT_TYPE_CERTIFICATE_REVOKED         44
#define TLS_ALERT_TYPE_CERTIFICATE_EXPIRED         45
#define TLS_ALERT_TYPE_CERTIFICATE_UNKNOWN         46
#define TLS_ALERT_TYPE_ILLEGAL_PARAMETER           47
#define TLS_ALERT_TYPE_UNKNOWN_CA                  48
#define TLS_ALERT_TYPE_ACCESS_DENIED               49
#define TLS_ALERT_TYPE_DECODE_ERROR                50
#define TLS_ALERT_TYPE_DECRYPT_ERROR               51
#define TLS_ALERT_TYPE_EXPORT_RESTRICTION          60
#define TLS_ALERT_TYPE_PROTOCOL_VERSION            70
#define TLS_ALERT_TYPE_INSUFFICIENT_SECURITY       71
#define TLS_ALERT_TYPE_INTERNAL_ERROR              80
#define TLS_ALERT_TYPE_USER_CANCELED               90
#define TLS_ALERT_TYPE_NO_RENEGOTIATION            100

/* TLS Handshake protocol msg types */
#define TLS_HANDSHAKE_TYPE_HELLO_REQUEST           0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO            1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO            2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE             11
#define TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE     12
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST     13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE       14
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY      15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE     16
#define TLS_HANDSHAKE_TYPE_FINISHED                20

/* TLS Record Header Definitions */

#define TLS_RECORD_HEADER_SIZE                     5

/* extract length field from TLS record */ 
#define TLS_RECORD_LENGTH_OFFSET                   3

/* extract encapsulated data from Record */ 
#define TLS_RECORD_DATA_OFFSET                     5 

/* Offset for the major version of the protocol */
#define TLS_RECORD_PROTOCOL_MAJ_VERSION_OFFSET     1

/* Offset for the minor version of the protocol */
#define TLS_RECORD_PROTOCOL_MIN_VERSION_OFFSET     2

/* handshake packet offset */
#define TLS_HANDSHAKE_HEADER_SIZE                  4 

/* Handshake Hello Message Offsets from beginning of packet */
#define SESSION_ID_OFFSET                          34

//#define RSA_ENCRYPT_PREMASTER_SECRET_LEN 46

/* ------------------------- SSLV2 ------------------------- */

/* SSL2 Message types */
#define SSL2_MT_ERROR			    	         0
#define SSL2_MT_CLIENT_HELLO		    	         1
#define SSL2_MT_CLIENT_MASTER_KEY	    	         2
#define SSL2_MT_CLIENT_FINISHED		    	         3
#define SSL2_MT_SERVER_HELLO		    	         4
#define SSL2_MT_SERVER_VERIFY		    	         5
#define SSL2_MT_SERVER_FINISHED		    	         6
#define SSL2_MT_REQUEST_CERTIFICATE	                 7
#define SSL2_MT_CLIENT_CERTIFICATE	                 8

/* SSL2 Error Codes */
#define SSL2_PE_NO_CIPHER                                0x0001
#define SSL2_PE_NO_CERTIFICATE                           0x0002
#define SSL2_PE_BAD_CERTIFICATE                          0x0004
#define SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE             0x0006

/* SSL2 record header offsets */
#define SSL2_2BYTE_RECORD_HEADER_SIZE                    2
#define SSL2_3BYTE_RECORD_HEADER_SIZE                    3

#define SSL2_ONE_CIPHER_SUITE_LEN                        3

/* SSL2 Client Hello Offsets */
#define SSL2_MSG_TYPE_OFFSET                             2
#define SSL2_CLIENT_HELLO_MAJOR_VER_OFFSET               3
#define SSL2_CLIENT_HELLO_MINOR_VER_OFFSET               4

#define SSL2_CLIENT_HELLO_CIPHER_SPEC_LEN_OFFSET         3
#define SSL2_CLIENT_HELLO_SESSION_ID_LEN_OFFSET          5
#define SSL2_CLIENT_HELLO_CHALLENGE_LEN_OFFSET           7
#define SSL2_CLIENT_HELLO_CIPHER_SPEC_OFFSET             9

/* SSL2 Server Hello Offsets */
#define SSL2_SERVER_HELLO_CERT_DATA_OFFSET               11

/* ------------ Macro Functions --------------------- */

#define MAX(x,y)  ((x) >= (y) ? (x) : (y))

/* taken from openssl:ssl_locl.h */

#define n2l3(c,l) ((l =(((unsigned long)(c[0]))<<16)| \
		  (((unsigned long)(c[1]))<< 8)| \
		  (((unsigned long)(c[2]))    )),c+=3)


/* ----------------- Structs -------------------------*/

/* ssl version numbers */
#define VERSION_SSL2              0
#define VERSION_SSL3              1
#define VERSION_TLS               2

/* offsets into the recv_change_cipher */
#define SERVER_RECV_CHANGE_CIPHER 0
#define CLIENT_RECV_CHANGE_CIPHER 1

/* key exchange algorithm */
#define RSA                       1
#define DH                        2

/* 
   struct containing the data for a connection 
*/
typedef struct ssl_connection 
{
    int client_fd;                /* socket descriptor for the client */
    int server_fd;
    int read_fd;                  /* which socket to read from */
    int write_fd;                 /* which socket to write to */

    int ssl_version;

    /* TLS */
    char recv_client_hello;       /* flags if we've received the client hello */
    char recv_server_hello;       /* need this to catch case of server doing only v2 */

    char recv_change_cipher[2];   /* set to 1 when change cipher 
				     packet received */
    char *recv_change;            /* which change cipher entry to set */
    char keyxchange_alg;          /* key exchange algorithm used */
    
    
    /* SSL2 */
    int ssl2_record_hdr_len;           /* whether record sent is padded */
    unsigned char ssl2_padding_len;    /* specified in a 3 bytes record hdr */
    char ssl2_packets_encrypted;       /* all packets will be encrypted. no parsing */

    char *record;
    unsigned int record_len;
}
ssl_connection;

/* 
   taken from dan boneh's utl_cert.h 

   for extracting and printing out the information obtained from the
   certificate
*/

typedef struct utl_cert_info 
{
    int keysize;
    
    char notAfter[64];
    char notBefore[64];
    
    X509_NAME *subj;
    char subj_DistName[256];
    
    X509_NAME *issuer;
    char issuer_DistName[256];
    
} 
UTL_CERT_INFO;

/*
  for storing the parameters specified on the command line
*/
typedef struct argv_params
{
    short local_port;

    char proxy; /* boolean. */
    char *remote_host_name_or_ip;
    short remote_port;
}
argv_params;


#endif /* SSLSNIFFER_H */
