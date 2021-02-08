#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined XWIN32
#include <Windows.h>
#endif

#if defined LINUX
#include <dlfcn.h>
#endif

#include <cm.h>

#if 0
typedef struct
{
	uint8_t mode;
	int8_t dispname[64];
	int8_t svcname[64];
	int8_t mname[128];
	int8_t exec[512];
}ServiceContext;

int32_t ServiceCreate(ServiceContext* s)
{
	int32_t e = -1;
	SC_HANDLE  hsvc = {0};
	SC_HANDLE  hmgr = {0};

	hmgr = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if ( hmgr != 0 )
	{
		hsvc = CreateService(hmgr,
													s->svcname,
													s->dispname,
													SERVICE_ALL_ACCESS,
													SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
													SERVICE_AUTO_START,
													SERVICE_ERROR_NORMAL,
													s->exec,
													0,0,0,0,0);

		if ( hsvc != 0 )
		{
			e = 0;
		}
	}
	CloseServiceHandle(hsvc);
	CloseServiceHandle(hmgr);
	return e;
}
int32_t ServiceDestroy(ServiceContext* s)
{
	int32_t e = -1;
	SC_HANDLE  hsvc = {0};
	SC_HANDLE  hmgr = {0};

	hmgr = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);

	if (hmgr != 0 )
	{
		hsvc = OpenService(hmgr, s->svcname, DELETE);
		if ( hsvc != 0 )
		{
			DeleteService(hsvc);
			e = 0;
		}
	}

	CloseServiceHandle(hsvc);
	CloseServiceHandle(hmgr);
	return e;
}
int32_t ServiceStart(ServiceContext* s)
{
	int32_t e = -1;
	SC_HANDLE  hsvc = {0};
	SC_HANDLE  hmgr = {0};

	hmgr = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if ( hmgr != 0 )
	{
		hsvc = OpenService(hmgr,s->svcname,SC_MANAGER_ALL_ACCESS);
		if ( hsvc != 0 )
		{
			if ( StartService(hsvc, 0, 0) == TRUE ) e = 0;
		}
	}
	CloseServiceHandle(hsvc);
	CloseServiceHandle(hmgr);

	return e;
}
int32_t ServiceStop(ServiceContext* s)
{
	int32_t e = -1;
	SERVICE_STATUS ss;
	SC_HANDLE  hsvc = {0};
	SC_HANDLE  hmgr = {0};

	hmgr = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if ( hmgr != 0 )
	{
		hsvc = OpenService(hmgr,s->svcname,SC_MANAGER_ALL_ACCESS);
		if ( hsvc != 0 )
		{
			if ( QueryServiceStatus(hsvc, &ss) == TRUE )
			{
				if ( ss.dwCurrentState != SERVICE_STOPPED )
				{
					ControlService(hsvc, SERVICE_CONTROL_STOP, &ss);
					e = 0;
				}
			}
		}
	}
	CloseServiceHandle(hsvc);
	CloseServiceHandle(hmgr);

	return e;
}



void ServiceHandler(ServiceContext* s)
{
	int32_t e = 0;
	if ( s->mode == 'c' )
	{
		e = ServiceCreate(s);
	}
	else if ( s->mode == 'd' )
	{
		e = ServiceDestroy(s);
	}
	else if ( s->mode == 's' )
	{
		e = ServiceStart(s);
	}
	else if ( s->mode == 'k' )
	{
		e = ServiceStop(s);
	}
}




void ServiceControl(int32_t argc, int8_t** argv)
{
	int32_t i = 0;
	ServiceContext sc = {0};
	GetModuleFileName(0, sc.mname, 64);

	for ( i=1 ; i<argc ; i++ )
	{
		if ( argv[i][0]=='-' )
		{
			if ( strncmp(&argv[i][1], "create", strlen("create")) == 0 )
			{
				sc.mode = 'c';
			}
			else if ( strncmp(&argv[i][1], "destroy", strlen("destroy")) == 0 )
			{
				sc.mode = 'd';
			}
			else if ( strncmp(&argv[i][1], "start", strlen("start")) == 0 )
			{
				sc.mode = 's';
			}
			else if ( strncmp(&argv[i][1], "stop", strlen("stop")) == 0 )
			{
				sc.mode = 'k';
			}
			else if ( strncmp(&argv[i][1], "display", strlen("display")) == 0 )
			{
				sprintf(sc.dispname, "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "service", strlen("service")) == 0 )
			{
				sprintf(sc.svcname, "%s", argv[i+1]);
				i++;
			}
			else if ( strncmp(&argv[i][1], "exec", strlen("exec")) == 0 )
			{
				sprintf(sc.exec, "%s", argv[i+1]);
				i++;
			}
		}
	}
	ServiceHandler(&sc);

}
#endif



void main(int32_t argc, int8_t** argv)
{
	static ServiceArgs sa = {0};
	//LOG(">>>> %d %s %s %s %s %s %s %s %s %s %s\r\n",
	//				argc, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10]);

	ArgParsing(argc, argv, &sa);

	setServiceArgs(&sa);

	if ( (sa.mode=='s') || (sa.mode=='S') )
	{
		SERVICE_TABLE_ENTRY STE[] = 
		{
			{sa.args[CM_SERVICE_NAME], (LPSERVICE_MAIN_FUNCTION)cmain},
			{0, 0}
		};
		StartServiceCtrlDispatcher(STE);
	}
	else
	if ( (sa.mode=='c') || (sa.mode=='C') )
	{
		cmain(argc, argv);
	}
}


