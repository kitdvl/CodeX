# How to use CodeX


#include <code.x.h>

int32_t (*codeXRun)(void** h, void* (*f)(void*,void*,void*,void*), void*);
int32_t (*codeXStop)(void** h);
int32_t (*putMessage)(void* h, void* m, void* w, void* l);
int32_t (*setMessage)(void* h, void* m, void* w, void* l);
int32_t (*getMessage)(void* h, void* m, void* w, void* l);

void displayBuffer(uint8_t* b, int32_t sz)
{
  int32_t i = 0;
  
  for ( i=0 ; i<sz ; i++ )
  {
    if (  i   &&  ((i%8)==0) ) printf("  ");
    if (  i   &&  ((i%16)==0) ) printf("\r\n");
    printf(" %02X", *(b+i));
  }
  printf("\r\n");
}


void* codeXStatus(void* h, void* msg, void* wparam, void* lparam)
{
	switch( HIWORD((uint32_t)msg) )
	{
	case XSOCKET:
		displayBuffer((uint8_t*)wparam, (int32_t)lparam);
		break;
	}
	return 0;
}


void programStop(void* h)
{
	putMessage(h, (void*)MAKELONG(DISABLE     , XSOCKET),  0,0);
	codeXStop(&h);
}


void main()
{
	int8_t msg[32];
  int32_t e = 0;
  uint32_t tid;
  void** h;
  HMODULE hdl;
  hdl = LoadLibrary("./code.X.x86");

  *(FARPROC*)&codeXRun          = GetProcAddress(hdl,"codeXRun");
  *(FARPROC*)&codeXStop         = GetProcAddress(hdl,"codeXStop");
  *(FARPROC*)&getMessage        = GetProcAddress(hdl,"codeXGetMessage");
  *(FARPROC*)&setMessage        = GetProcAddress(hdl,"codeXSetMessage");
  *(FARPROC*)&putMessage        = GetProcAddress(hdl,"codeXPutMessage");

	codeXRun(&h, codeXStatus, 0);

	setMessage(h, (void*)MAKELONG(XM_DELAY_0    , XSOCKET),   (void*)"3000",               (void*)strlen("3000"));
	setMessage(h, (void*)MAKELONG(XM_BUFFER_SZ  , XSOCKET),   (void*)0,                    (void*)64);
	setMessage(h, (void*)MAKELONG(XM_IP         , XSOCKET),   (void*)"127.0.0.1",          (void*)strlen("127.0.0.1"));
	setMessage(h, (void*)MAKELONG(XM_PORT       , XSOCKET),   (void*)"7870",               (void*)strlen("7870"));
	setMessage(h, (void*)MAKELONG(XM_PROTO      , XSOCKET),   (void*)"TCP",                (void*)strlen("TCP"));
	setMessage(h, (void*)MAKELONG(XM_CSTYPE     , XSOCKET),   (void*)"SERVER",             (void*)strlen("SERVER"));
	//setMessage(h, (void*)MAKELONG(XM_CSTYPE     , XSOCKET),   (void*)"CLIENT",             (void*)strlen("CLIENT"));
	setMessage(h, (void*)MAKELONG(XM_CASTTYPE   , XSOCKET),   (void*)"UNICAST",            (void*)strlen("UNICAST"));
	setMessage(h, (void*)MAKELONG(XM_ECHOMODE   , XSOCKET),   (void*)"0",                  (void*)strlen("0"));
	setMessage(h, (void*)MAKELONG(XM_KEY        , XSOCKET),   (void*)"shinbaad@gmail.com", (void*)strlen("shinbaad@gmail.com"));
	setMessage(h, (void*)MAKELONG(ENABLE        , XSOCKET),  0, 0);



	/// <summary>
	/// in case of CLIENT
	/// </summary>
	while ( 1 )
	{
		sprintf(msg, "Hello World %d \r\n", e);
		printf(" --->   %s", msg);
		setMessage(h, (void*)MAKELONG(WRITE   , XSOCKET),   (void*)msg,            (void*)strlen(msg));

		printf("press any key to conitnue....");
		getchar();

		e++;
	}

}
