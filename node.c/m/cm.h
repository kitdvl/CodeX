#ifndef __CM_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__
#define __CM_H_F2DBDC40_6196_4E67_A689_D31A9310BEC0__

#if defined __cplusplus
extern "C"
#endif
#if defined WIN32 || defined WINCE
__declspec(dllexport)
#endif
void* cmain(int argc, char** argv);


enum
{
	CM_CONFIG_PATH = 0,
	CM_CODEX_PATH,
	CM_EXTDLL_PATH,
	CM_LOG_PATH,
	CM_DISPLAY_NAME,
	CM_SERVICE_NAME,
	CM_MAX
};

typedef struct
{
	uint8_t args[CM_MAX][128];	
	uint8_t mode;
}ServiceArgs;


void ArgParsing(int32_t argc, int8_t** argv, ServiceArgs* sa);
void setServiceArgs(ServiceArgs* p);


#endif