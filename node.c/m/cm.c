#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined XWIN32
#include <Windows.h>
#endif

#if defined LINUX
#include <dlfcn.h>
#endif
#include <code.x.h>


#include <cm.h>

#if defined XWIN32
#define __MODULE_NAME__    "./code.X.sifr.x86.dll"
#endif

#if defined LINUX
#define __MODULE_NAME__    "./code.X.sifr.x32.so"
#endif


typedef struct
{
	void* hdl;
	void* h;

	int32_t (*setMessage)(void*,void*,void*,void*);
	int32_t (*getMessage)(void*,void*,void*,void*);

	void* (*dmain)(void*, void**, void**, void**, void**, void**);

	void* (*Callback)(void* h, void* m, void* w, void* l);
	void* (*iohandler[2])(void* h,int32_t fd, uint8_t* b, int32_t sz);
	void* (*iocontroller[2])(void* h, void* m, void* w, void* l);
	void* (*Log)(void* fp, int8_t* pfx, const int8_t* fmt,...);
	void* obj;



	uint8_t _logName[128];
}SubCodeX;


typedef struct
{
	void*  hdl;
	void*  h;
	ServiceArgs* psa;
	uint8_t _logFlag;
	uint8_t _logExpire;

	int32_t (*setMessage)(void*,void*,void*,void*);
	int32_t (*getMessage)(void*,void*,void*,void*);
	int32_t (*getPrefix)(int8_t* path);
	int32_t (*getFiles)(int8_t* dname, int8_t* list, int32_t* count);
	int32_t (*getDlmtrStr)(int8_t* str, int8_t dlmtr, int32_t idx, int8_t* out);
	void    (*getFileExt)(int8_t* fname, int8_t* output);
	void*   (*threadCreate)(void* (*f)(void*), void* arg, void* id);
	void*   (*logWrite)(int8_t* ppath, int8_t* fname, int8_t* pfname, void** pfp, int8_t* pfx, uint32_t mode, const int8_t* fmt, ...);

	int32_t (*lockInitia)(void* crit);
	int32_t (*lockFinelia)(void* crit);
	int32_t (*lock)(void* crit);
	int32_t (*unlock)(void* crit);
	SubCodeX*  psm;
	int32_t    psm_cnt;

	uint32_t   svc_status;



  #if defined LINUX
  pthread_mutex_t crit;
  #endif
  #if (defined XWIN32 || defined WINCE)
  CRITICAL_SECTION  crit;
  #endif


	//FILE*       logfp;
}CodeX;

static CodeX cx = {0};


void CalcElapsedMonth()
{
  uint32_t YY=2021, MM = 5, M = 1;
  uint32_t _YY= 0, _MM = 0;
  for ( M=0 ; M<60 ; M++ )
  {
    _MM = ((12*(M/12+1) - ((M%12)-MM))%12);
    _MM = _MM==0?12:_MM;
    _YY = YY-(12 - (MM-M))/12;
    printf(" %4d.%02d   ->  %02d  ->   %4d.%02d \r\n", YY,MM,M,_YY,_MM);
  }
 
}

void* Log(void* fp, int8_t* pfx, const int8_t* fmt,...)
{
  va_list args;
	static int8_t tmp[512] = {0};
	int8_t _args[8192] = {0};
	uint32_t flg = 0;
	if (cx.psa->args[CM_LOG_PATH]==0 )return 0;

	cx.lock((void*)&cx.crit);
	va_start(args, fmt);
	vsprintf(_args, fmt, args);
  va_end(args);

	if ( (cx._logFlag=='Y') || (cx._logFlag=='y') ) flg = 0x80000000;
	else if ( (cx._logFlag=='M') || (cx._logFlag=='m') ) flg = 0xC0000000;
	else if ( (cx._logFlag=='D') || (cx._logFlag=='d') ) flg = 0xE0000000;

	cx.logWrite(cx.psa->args[CM_LOG_PATH], cx.psm->_logName,  tmp, (void**)fp, pfx, flg|cx._logExpire, _args);
	cx.unlock((void*)&cx.crit);

	return 0;
}

void* codeXCallback(void* h, void* m, void* w, void* l)
{
	int32_t e = 0;
	int32_t i[MAX_MODULES]={0};
	CodeX* p = (CodeX*)h;

	//{
	//	char a[128];
	//	sprintf(a, "[%08X] \r\n", HIWORD((uint32_t)m));
	//	OutputDebugString(a);
	//}

	switch( HIWORD((uint32_t)m) )
	{
	case XWEBSOCKET:
		for ( i[HIWORD((uint32_t)m)]=0 ; i[HIWORD((uint32_t)m)]<p->psm_cnt ; i[HIWORD((uint32_t)m)]++)
		{
			if ( (p->psm+i[HIWORD((uint32_t)m)]) != 0 )
			{
				if ( *(p->psm+i[HIWORD((uint32_t)m)])->Callback ) ((p->psm+i[HIWORD((uint32_t)m)])->Callback)((p->psm+i[HIWORD((uint32_t)m)])->obj,m,w,l);
				if ( *(p->psm+i[HIWORD((uint32_t)m)])->iohandler[1] != 0 ) e = 0xE0000001;
			}
		}
		break;
	case XHTTPD:
		for ( i[HIWORD((uint32_t)m)]=0 ; i[HIWORD((uint32_t)m)]<p->psm_cnt ; i[HIWORD((uint32_t)m)]++)
		{
			if ( (p->psm+i[HIWORD((uint32_t)m)]) != 0 )
			{
				if ( *(p->psm+i[HIWORD((uint32_t)m)])->Callback ) ((p->psm+i[HIWORD((uint32_t)m)])->Callback)((p->psm+i[HIWORD((uint32_t)m)])->obj,m,w,l);
				if ( *(p->psm+i[HIWORD((uint32_t)m)])->iohandler[1] != 0 ) e = 0xE0000001;
			}
		}
		break;


	default:
		if ( *(p->psm+i[HIWORD((uint32_t)m)])->Callback ) ((p->psm+i[HIWORD((uint32_t)m)])->Callback)((p->psm+i[HIWORD((uint32_t)m)])->obj,m,w,l);
		if ( *(p->psm+i[HIWORD((uint32_t)m)])->iohandler[1] != 0 ) e = 0xE0000001;
		break;
	}

	return (void*)e;
}

void* NodeServer(CodeX* p)
{
	int32_t    e = 0;

	p->setMessage(0, MAKELONG(SYSTEM_LIBRARY, CODEX), p->psa->args[CM_CODEX_PATH], strlen(p->psa->args[CM_CODEX_PATH]));
	e = p->setMessage(&p->h, (void*)MAKELONG(INIT,CODEX), codeXCallback, p);
	//e = p->setMessage(p->h, (void*)MAKELONG(XM_BUFFER_SZ  ,   XWEBSOCKET), 0,                (void*)2048);
	e = p->setMessage(p->h, (void*)MAKELONG(XML_INFO,CODEX), p->psa->args[CM_CONFIG_PATH], strlen(p->psa->args[CM_CONFIG_PATH]));

	return p->h;
}


void* nodeSetMessage(void* h, void* m, void* w, void* l)
{
	return ((SubCodeX*)h)->setMessage(((SubCodeX*)h)->h, m, w, l);
}
void* nodeGetMessage(void* h, void* m, void* w, void* l)
{
	return ((SubCodeX*)h)->getMessage(((SubCodeX*)h)->h, m, w, l);
}


void* wsRead(void* h, int32_t fd, uint8_t* b, int32_t sz)
{
	int32_t e = 0;
	SubCodeX* p = (SubCodeX*)h;

	p->getMessage(p->h, (void*)MAKELONG(READ, XWEBSOCKET), (void*)b, (void*)sz);

	return (void*)e;
}


void* wsWrite(void* h, int32_t fd, uint8_t* b, int32_t sz)
{
	int32_t e = 0;
	SubCodeX* p = (SubCodeX*)h;

	e = p->setMessage(p->h, (void*)MAKELONG(FDSCRPTR, XWEBSOCKET), (void*)fd, (void*)0);
	e = p->setMessage(p->h, (void*)MAKELONG(WRITE, XWEBSOCKET), (void*)b, (void*)sz);

	//wnd.codeX.setMessage(wnd.codeX.h, (void*)MAKELONG(FDSCRPTR, XWEBSOCKET), (void*)(wnd.codeX.modul[XWEBSOCKET].fdset+idx)->a[0], 0);
	//e = wnd.codeX.setMessage(wnd.codeX.h, (void*)MAKELONG(WRITE, XWEBSOCKET), (void*)b, (void*)sz);


	return (void*)e;
}




void* SubThread(void* arg)
{
	SubCodeX* p = (SubCodeX*)arg;

	p->dmain(p, &p->Callback, p->iohandler, p->iocontroller, &p->Log, &p->obj);

	return 0;
}

void LoadProcess(CodeX* c, SubCodeX* p, int8_t* path)
{
	uint32_t id = 0;

	p->hdl = LoadLibrary(path);
	*(FARPROC*)&p->dmain = GetProcAddress(p->hdl, "dmain");

	p->setMessage = c->setMessage;
	p->getMessage = c->getMessage;

	p->Callback = 0;
	p->iohandler[1] = wsRead;
	p->iohandler[0] = wsWrite;

	p->iocontroller[0] = nodeSetMessage;
	p->iocontroller[1] = nodeGetMessage;
	p->Log = Log;

	p->h = NodeServer(c);

	c->threadCreate(SubThread, p, &id);
}

void UnloadProcess(CodeX* c, SubCodeX* p)
{
	int32_t e = 0;

	e = p->setMessage(&p->h, (void*)MAKELONG(RELEASE,CODEX), 0, 0);
}



void* StartProcess(void* arg)
{
	int32_t   e = 0;
	CodeX*    pcx = (CodeX*)arg;
	int8_t    lst[2048] = {0};
	int32_t   lcnt = 0;
	int32_t   i=0, ii=0;
	int8_t    fname[1024] = {0};
	int8_t    fpath[1024] = {0};
	int8_t    tmp[32] = {0};


	#if defined LINUX
	hdl = dlopen(__MODULE_NAME__, RTLD_LAZY);
	if ( hdl == 0 )
	{
		printf("dlopen fail %s \r\n", dlerror());
		return;
	}
	pcx->setMessage = dlsym(hdl, "codeXSetMessage");
	pcx->getMessage = dlsym(hdl, "codeXGetMessage");
	#endif

	#if defined XWIN32
	pcx->hdl = LoadLibrary(pcx->psa->args[CM_CODEX_PATH]);
	if ( pcx->hdl == 0 )
	{
		return;
	}
	*(FARPROC*)&pcx->setMessage   = GetProcAddress(pcx->hdl, "codeXSetMessage");
	*(FARPROC*)&pcx->getMessage   = GetProcAddress(pcx->hdl, "codeXGetMessage");
	*(FARPROC*)&pcx->getPrefix    = GetProcAddress(pcx->hdl, "get_prefix");
	*(FARPROC*)&pcx->getFiles     = GetProcAddress(pcx->hdl, "get_files");
	*(FARPROC*)&pcx->getDlmtrStr  = GetProcAddress(pcx->hdl, "get_dlmtr_str");
	*(FARPROC*)&pcx->getFileExt   = GetProcAddress(pcx->hdl, "get_fileext");
	*(FARPROC*)&pcx->threadCreate = GetProcAddress(pcx->hdl, "thread_create");
	*(FARPROC*)&pcx->logWrite     = GetProcAddress(pcx->hdl, "log_write_ex");
	*(FARPROC*)&pcx->lockInitia   = GetProcAddress(pcx->hdl, "lock_init");
	*(FARPROC*)&pcx->lockFinelia  = GetProcAddress(pcx->hdl, "lock_final");
	*(FARPROC*)&pcx->lock         = GetProcAddress(pcx->hdl, "lock");
	*(FARPROC*)&pcx->unlock       = GetProcAddress(pcx->hdl, "unlock");
	#endif


	pcx->lockInitia((void*)&pcx->crit);


	pcx->getFiles(pcx->psa->args[CM_EXTDLL_PATH], lst, &lcnt); 

	for ( i=0 ; i<lcnt ; i++ )
	{
		pcx->getDlmtrStr(lst, ':', i, fname);
		pcx->getFileExt(fname, tmp);

		if ( strncmp(tmp, "dll", 3) == 0 )
		{
			pcx->psm_cnt++;
		}
	}

	pcx->psm = (SubCodeX*)calloc(pcx->psm_cnt, sizeof(SubCodeX));
	memset(pcx->psm, 0, pcx->psm_cnt*sizeof(SubCodeX));

	for ( i=0, ii=0 ; i<lcnt ; i++ )
	{
		pcx->getDlmtrStr(lst, ':', i, fname);
		pcx->getFileExt(fname, tmp);
		if ( strncmp(tmp, "dll", 3) == 0 )
		{
			sprintf((pcx->psm+ii)->_logName, "%s", fname);
			#if defined XWIN32
			sprintf(&fpath[e], "%s\\%s", pcx->psa->args[CM_EXTDLL_PATH],fname);
			#endif
			#if defined LINUX
			sprintf(&fpath[e], "%s/%s", pcx->psa->args[CM_EXTDLL_PATH],fname);
			#endif

			LoadProcess(pcx, (pcx->psm+ii), fpath);
			ii++;
		}
	}

	return 0;
}


void* StopProcess(void* arg)
{
	int32_t   e = 0;
	int32_t   i = 0;
	CodeX*    pcx = (CodeX*)arg;

	for ( i=0 ; i<pcx->psm_cnt ; i++ )
	{
		UnloadProcess(pcx, (pcx->psm+i));
	}
	free(pcx->psm);

	FreeLibrary(pcx->hdl);

	pcx->lockFinelia((void*)&pcx->crit);

	return 0;
}
#if defined XWIN32
static uint32_t status_service;
static uint32_t hsvc = SERVICE_STOPPED;
#endif

#if defined XWIN32
VOID SET_SERVICE_STATE(SERVICE_STATUS_HANDLE hd, DWORD dwState)
{
	SERVICE_STATUS ss;
	ss.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
	ss.dwCurrentState=dwState;
	ss.dwControlsAccepted=SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
	ss.dwWin32ExitCode=0;
	ss.dwServiceSpecificExitCode=0;
	ss.dwCheckPoint=0;
	ss.dwWaitHint=0;
        
	status_service = dwState;
	SetServiceStatus(hd, &ss);
}
#endif

#if defined XWIN32
DWORD GET_SERVICE_STATE()
{
	return status_service;
}
#endif

#if defined XWIN32
uint32_t WINAPI __ServiceHandler(uint32_t ctrl, uint32_t evnt, void* p, void* ctx)
{
	switch(ctrl)
	{
	case SERVICE_CONTROL_PAUSE:
		SET_SERVICE_STATE(hsvc, SERVICE_PAUSE_PENDING, 0);
		SET_SERVICE_STATE(hsvc, SERVICE_PAUSED);
		break;

	case SERVICE_CONTROL_CONTINUE:
		SET_SERVICE_STATE(hsvc, SERVICE_CONTINUE_PENDING, 0);
		SET_SERVICE_STATE(hsvc, SERVICE_RUNNING);
		break;


	case SERVICE_CONTROL_STOP:
		StopProcess(&cx);
		SET_SERVICE_STATE(hsvc, SERVICE_STOP_PENDING, 0);
		SET_SERVICE_STATE(hsvc, SERVICE_STOPPED);
		break;

	default:
		break;
	}

	return NO_ERROR;
}
#endif

#if 0
void ArgParsing(int32_t argc, int8_t** argv, ServiceArgs* sa)
{
	int32_t i = 0;
	for ( i=1 ; i<argc ; i++ )
	{
		if ( argv[i][0]=='-' )
		{
			if ( strncmp(&argv[i][1], "display", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_DISPLAY_NAME], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "service", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_SERVICE_NAME], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "config", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_CONFIG_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "codex", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_CODEX_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "extdll", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_EXTDLL_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "log", strlen(&argv[i][1])) == 0 )
			{
				sprintf(sa->args[CM_LOG_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "log_expire", strlen(&argv[i][1])) == 0 )
			{
				//sprintf(sa->args[CM_LOG_EXPIRE], "%s", argv[i+1]);
				cx._logFlag = argv[i+1][0];
				cx._logExpire = atoi(&argv[i+1][1]);
				i++;
			}
		}
	}
}
#endif


void ArgParsing(int32_t argc, int8_t** argv, ServiceArgs* sa)
{
	int32_t i = 0;
	for ( i=1 ; i<argc ; i++ )
	{
		if ( argv[i][0]=='-' )
		{
			if ( argv[i][1] == 'd' ) ///// display
			{
				sprintf(sa->args[CM_DISPLAY_NAME], "%s", argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 's' ) //// service
			{
				sprintf(sa->args[CM_SERVICE_NAME], "%s", argv[i+1]);
				i++;
			}
			else if ( argv[i][1] == 'c' ) //// config
			{
				sprintf(sa->args[CM_CONFIG_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( (argv[i][1] == 'X') || (argv[i][1] =='x') ) //// codex
			{
				sprintf(sa->args[CM_CODEX_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( (argv[i][1] == 'P') || (argv[i][1] =='p') ) //// extern dll path
			{
				sprintf(sa->args[CM_EXTDLL_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( argv[i][1] == 'l' ) //// log
			{
				sprintf(sa->args[CM_LOG_PATH], "%s", argv[i+1]);
				i++;
			}
			else if ( argv[i][1] == 'e' ) //// log_expire
			{
				cx._logFlag = argv[i+1][0];
				cx._logExpire = atoi(&argv[i+1][1]);
				i++;
			}
			else if ( (argv[i][1] == 'M') || (argv[i][1] == 'm') ) //// mode
			{
				sa->mode = argv[i+1][0];
				i++;
			}
		}
	}
}

void setServiceArgs(ServiceArgs* p)
{
	cx.psa = p;
}

void* cmain(int argc, char** argv)
{

	if ( (cx.psa->mode=='s') || (cx.psa->mode=='S') )
	{
		#if defined XWIN32
		hsvc = RegisterServiceCtrlHandlerEx(cx.psa->args[CM_SERVICE_NAME], __ServiceHandler, 0);
		if ( hsvc == 0 )
		{
		}
		StartProcess(&cx);
		SET_SERVICE_STATE(hsvc, SERVICE_RUNNING);

		for ( ; GET_SERVICE_STATE() != SERVICE_STOPPED; )
		{
			if ( GET_SERVICE_STATE() == SERVICE_PAUSED )
			{
				Sleep(1000);
				continue;
			}
			Sleep(1000);
		}
		#endif
	}
	else if ( (cx.psa->mode=='c') || (cx.psa->mode=='C') )
	{
		StartProcess(&cx);
		while ( 1 )
		{
			#if defined XWIN32
			Sleep(1);
			#endif
			#if defined LINUX
			usleep(1);
			#endif
		}
	}
	return 0;
}



#if 0
sc create WAAS_WSD binpath= "d:\github\projectX\tools\codeXwsd\out\codeXwsd.x86.exe -display WAAS_WSD -service WAAS_WSD -config D:\github\projectX\tools\codeXwsd\config.xml -codex D:\github\projectX\tools\codeXwsd\out\code.X.sifr.x86.dll -extdll D:\github\projectX\app\manntel\diot\out" start= auto


sc create WAAS_WSD binpath= "f:\xlocal\projectX\tools\codeXwsd\out\codeXwsd.x86.exe -display WAAS_WSD -service WAAS_WSD -config f:\xlocal\projectX\tools\codeXwsd\config.xml -codex f:\xlocal\projectX\tools\codeXwsd\out\code.X.sifr.x86.dll -extdll f:\xlocal\projectX\app\manntel\diot\out" start= auto
#endif