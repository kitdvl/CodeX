CC= gcc
PFLAGS= -cache-dir=/tmp/${USER} 
PURIFY= purify ${PFLAGS}
INCS= -I.
INCS+= -I/usr/xlocal/codeX/openssl/v1.1.1k/x32/include
INCS+= -I/usr/xlocal/codeX/openssl/v1.1.1k/x32/include/openssl
LIBS= -L/usr/xlocal/codeX/openssl/v1.1.1k/x32/lib -L. -lnsl -lssl -lcrypto -lutl -lpthread -ldl
SRCS= sslsniffer.c 
OBJS= ${SRCS:.c=.o}
BINS= sslsniffer
UTL_LIB= libutl.a
UTL_SRCS= general_utilities.c net_utilities.c
AR= ar
ARFLAGS= rs
BINS.PURIFY= sslpure

CCFLAGS= -m32 -g -Wall -O3 -pedantic ${INCS} 

all: $(UTL_LIB) ${BINS} 

%.o: %.c
	${CC} ${CCFLAGS} -c $<

${BINS}: ${OBJS}
	${CC} ${CCFLAGS} -o $@  ${OBJS} ${LIBS} 

$(UTL_LIB): general_utilities.o net_utilities.o
	${AR} ${ARFLAGS} $@ general_utilities.o net_utilities.o

clean:
	@echo "Removing objects..."
	rm -f ${BINS} ${OBJS} general_utilities.o net_utilities.o ${UTL_LIB} core 

tags TAGS:
	etags ${SRCS} ${UTL_SRCS}

