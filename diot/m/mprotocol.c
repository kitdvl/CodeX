#include <util.h>

#define MAX_BUF_IDX    32
#define MAX_BUF_SZ     128
/***
02 10 0F 01  00 42 00 42
00 42 01 03  0A 00 00 00
00 02 0A 03  0A
***/
int32_t on_protcol_check_HEX(uint8_t* se, int32_t maxsz, uint32_t* SR, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz)
{
  int32_t i = 0;
  int32_t e = -1;
  //printf(" maxsz -> %d\r\n", maxsz);
  //printf(" sz    -> %d\r\n", sz);
  for (i = 0; i < sz; i++)
  {
    //printf(" %3d -> %3d,  %08X  ---> [%02X] \r\n", i, *pos, *SR, *(b+i) );
    if (((*SR & 0x80000001) == 0) && (*(b + i) == *(se + 0)))
    {
      *pos = 0;
      *SR |= 0x80000000;
    }

    if ((*SR) & 0x80000000)
    {
      *(o + (*pos)) = *(b + i);
      (*pos)++;
      *osz = *pos;
    }

    if (((*SR) & 0x80000000) && ((*(b + i) == *(se + 1)) && (*pos) == maxsz))
    {
      *SR |= 0x00000001;
    }
  }
  *pos %= maxsz;

  if (((*SR) & 0x80000001) == 0x80000001)
  {
    e = *pos;
    *pos = 0;
    *SR &= 0x7FFFFFFE;
  }
  return e;
}



int32_t on_protcol_check(uint8_t* se, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz, void* cbf(void*,int8_t*, int32_t, int32_t),void* obj)
{
  int32_t i = 0;
  int32_t e = -1;
  int32_t _pos = 0;

  #if DEBUG_LOCAL
  {
    int8_t temp[1024];
    raw_buffer(b, sz, temp);
    trace("on_protocol_check 1 | %s\r\n", temp);
  }
  #endif


  for (i = 0; i < sz; i++)
  {
    for (; ((*pos)==0) && (*(b+i)!=0) && (*(b+i)!=*(se+0)); i++);

    #if DEBUG_LOCAL
    {
      int8_t temp[1024];
      sprintf(temp, "[ %4d -> %4d, %4d, %02X ]", i, *pos, _pos, (uint8_t)*(b+i));
      trace("on_protocol_check 2 | %s\r\n", temp);
    }
    #endif

    if ((*pos)==0)
    {
      if (*(b+i) == *(se+0))
      {
        *(o+*(pos)) = *(b+i);
        _pos = i;
        (*pos)++;
        #if DEBUG_LOCAL
        trace("on_protocol_check 3 | STX\r\n");
        #endif
        continue;
      }
    }

    if (*pos)
    {
      *(o + *(pos)) = *(b+i);
      (*pos)++;
      #if DEBUG_LOCAL
      trace("  %08X : %08X \r\n", *(b+i), *(se+1));
      #endif
      if ( (uint8_t)(*(b+i)) == *(se+1) )
      {
        #if DEBUG_LOCAL
        {
          int8_t temp[1024];
          raw_buffer(o, *pos, temp);
          trace("---->  %d >> %s\r\n", *pos, temp);
        }
        #endif
				if ( cbf  )
				{
					e = (int32_t)cbf(obj, o, (*pos), 0xE0000001);
				}
				else
				{
					e = 0;
				}
				if ( e == 0 )
				{

					#if DEBUG_LOCAL
					{
						int8_t temp[1024];
						sprintf(temp, "ETX %d\r\n", (*pos));
            trace("on_protocol_check 4 | %s\r\n", temp);
					}
					#endif

					#if DEBUG_LOCAL
					{
						int8_t temp[1024];
            raw_buffer(o, *pos, temp);
            trace("on_protocol_check 5 | [ETX] %s\r\n", temp);
					}
					#endif

					//e = *pos;
					i++;
					e = i;
					(*osz) = *pos;
					(*pos) = 0;
					break;
				}
				else if ( e == -2 )
				{
					//i++;
					//(*osz) = *pos;
					(*pos) = 0;
				}
      }
    }
    #if DEBUG_LOCAL
    trace("\r\n");
    #endif
  }


  #if  DEBUG_LOCAL
  //printf("[ %4d -> %4d, %4d, %4d ]\r\n", i, e, *pos, *osz);
  {
    int8_t temp[1024];
    sprintf(temp, "[ %4d -> %4d, %4d, %4d, %4d, %4d ]\r\n", i, e, *pos, _pos, *osz, sz);
    trace("on_protocol_check 6 | %s\r\n", temp);
  }
  #endif


  //if (e < 0)
  //{
  //  int32_t oi = 0;
  //  for (i = _pos, oi = 0; oi < sz; oi++, i++)
  //  {
  //    *(o + oi) = *(b + i);
  //  }
  //  //(*pos)++;
  //  #if DEBUG_LOCAL
  //  {
  //    int8_t temp[1024];
  //    raw_buffer(b, sz, temp);
  //    i = i*3;
  //    temp[i] = ' '; i++;
  //    temp[i] = ':'; i++;
  //    temp[i] = ' '; i++;
  //    raw_buffer(o, oi, &temp[i]);
  //    trace("on_protocol_check 7 | *****  %s\r\n", temp);
  //  }
  //  #endif
  //}
  return e;
}

int32_t on_protocol_proc(uint8_t* protocol_info, int8_t* b, int32_t sz, int8_t* o, int32_t* pos, void* cbf(void*, int8_t*, int32_t, int32_t), void* obj)
{
  int32_t e = 0;
  int32_t osz = 0;
	int32_t i=0;
	for ( ; ; )
	{
    #if DEBUG_LOCAL
    {
      int8_t temp[1024];
      raw_buffer(b+i,sz-i, temp);
      trace("on_shof_protocol_proc ----- | %s\r\n", temp);
    }
    #endif
  	e = on_protcol_check(protocol_info, b+i, sz-i, pos, o, &osz, cbf, obj);
    #if DEBUG_LOCAL
    {
      int8_t temp[1024];
      raw_buffer(o+(*pos),osz, temp);
      trace("on_shof_protocol_proc [%3d] | %s\r\n", e, temp);
    }
    #endif
  	if ( e > 0 )
  	{
			i += e;
      #if DEBUG_LOCAL
      {
        int8_t temp[1024];
        raw_buffer(o+(*pos),osz, temp);
        trace("on_shof_protocol_proc check | %s\r\n", temp);
      }
      #endif
			if ( cbf )
      {
        cbf(obj, o+(*pos), osz, 0);
      }
  	}
		else
		{
      //{
      //  int8_t temp[1024];
      //  raw_buffer(o+(*pos),osz, temp);
      //  trace("on_shof_protocol_proc check break | %d %s\r\n", e, temp);
      //}
			break;
		}
	}

  return e;
}




#if 0
int32_t on_protcol_check(uint8_t* se, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz, void* cbf(int8_t*, int32_t))
{
  int32_t i = 0;
  int32_t e = -1;
  int32_t _pos = 0;

#if DEBUG_LOCAL
  {
    int8_t temp[1024];
    //fprint_buffer("on_protocol_check buffer", b, sz, 0, 16);
    fprint_raw_buffer("on_protocol_check buffer", b, sz, temp);
    OutputDebugString(temp);
    OutputDebugString("\r\n");
  }
#endif

  for (i = 0; i < sz; i++)
  {
#if DEBUG_LOCAL
    {
      int8_t temp[1024];
      //printf("[ %4d -> %4d, %02X ]\r\n", i, *pos, (uint8_t)*(b + i));
      sprintf(temp, "[ %4d -> %4d, %4d, %02X ]", i, *pos, _pos, (uint8_t)*(b + i));
      OutputDebugString(temp);
    }
#endif
    if ((*pos) == 0)
    {
      if (*(b + i) == *(se + 0))
      {
        *(o + *(pos)) = *(b + i);
        _pos = i;
        (*pos)++;
#if DEBUG_LOCAL
        OutputDebugString("STX \r\n");
#endif
        continue;
      }
    }

    if (*pos)
    {
      *(o + *(pos)) = *(b + i);
      (*pos)++;
      if (*(b + i) == *(se + 1))
      {
        if (cbf(o, (*pos)) == 0)
        {

#if DEBUG_LOCAL
          {
            int8_t temp[1024];
            sprintf(temp, "ETX %d\r\n", (*pos));
            OutputDebugString(temp);
          }
#endif

#if DEBUG_LOCAL
          {
            int8_t temp[1024];
            fprint_raw_buffer("on_protocol_check ETX", o, *pos, temp);
            OutputDebugString(temp);
            OutputDebugString("\r\n");
          }
#endif

          //e = *pos;
          i++;
          e = i;
          (*osz) = *pos;
          (*pos) = 0;
          break;
        }
      }
    }
#if DEBUG_LOCAL
    OutputDebugString("\r\n");
#endif
  }


#if  DEBUG_LOCAL
  //printf("[ %4d -> %4d, %4d, %4d ]\r\n", i, e, *pos, *osz);
  {
    int8_t temp[1024];
    sprintf(temp, "[ %4d -> %4d, %4d, %4d, %4d, %4d ]\r\n", i, e, *pos, _pos, *osz, sz);
    OutputDebugString(temp);
  }
#endif


  if (e < 0)
  {
    int32_t oi = 0;
    for (i = 0, oi = 0; oi < sz; oi++, i++)
    {
      *(o + oi) = *(b + i);
    }
    //(*pos)++;
#if DEBUG_LOCAL
    {
      int8_t temp[1024];
      fprint_raw_buffer("on_protocol_check ******", o, sz, temp);
      OutputDebugString(temp);
      OutputDebugString("\r\n");
    }
#endif
  }
  return e;
}
#endif

#if 0
int32_t on_protcol_check(uint8_t* se, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz, void* cbf(int8_t*, int32_t))
{
  int32_t i = 0;
  int32_t e = -1;
  {
    int8_t tmp[4096];
    fprint_raw_buffer("bbuf", b, sz, tmp);
    OutputDebugString(tmp);
    OutputDebugString("\r\n");
  }

  if ( *(pos+0) )
  {
    int8_t tmp[4096];
    fprint_raw_buffer("****", o - *(pos + 0), 32, tmp);
    OutputDebugString(tmp);
    OutputDebugString("\r\n");
  }


  for (i = 0; i < sz; i++)
  {
    if ((*(pos+0) == 0) && (*(b + i) == *(se + 0)))
    {
      *(pos + 0) = 0;
      *(o + *(pos + 0)) = *(b + i);
      (*(pos + 0))++;
      continue;
    }

    if (*(pos+0))
    {
      *(o + *(pos + 0)) = *(b + i);
      (*(pos + 0))++;

      if (*(b + i) == *(se + 1))
      {
        if (cbf(o, *(pos + 0)) == 0)
        {
          e = ++i;
          *osz = *(pos + 0);
          *(pos + 0) = 0;
          break;
        }
      }
    }
  }


  if ( i && *(pos + 0))
  {
    int32_t oi = 0;
    for ( i = *(pos + 0), oi = 0 ;oi<sz ; oi++, i++)
    {
      *(o+oi) = *(b+i);
    }
    //*(pos + 0) = _pos;

    {
      int8_t tmp[4096];
      fprint_raw_buffer("obuf", o, *osz, tmp);
      OutputDebugString(tmp);
      OutputDebugString("\r\n");
    }

  }


  return e;
}
#endif





int32_t on_protcol_checker(uint8_t* se, int8_t* b, int32_t sz, int32_t* pos, int8_t* o, int32_t* osz, void* cbf(int8_t*, int32_t))
{
  int32_t i = 0;
  int32_t e = -1;
  int32_t _pos = 0;

  for (i = 0; i < sz; i++)
  {
    if ((*pos) == 0)
    {
      if (*(b + i) == *(se + 0))
      {
        *(o + *(pos)) = *(b + i);
        _pos = i;
        (*pos)++;
        continue;
      }
    }

    if (*pos)
    {
      *(o + *(pos)) = *(b + i);
      (*pos)++;
      if (*(b + i) == *(se + 1))
      {
        if (cbf(o, (*pos)) == 0)
        {
          i++;
          e = i;
          (*osz) = *pos;
          (*pos) = 0;
          break;
        }
      }
    }
  }
  if (e < 0)
  {
    int32_t oi = 0;
    for (i = 0, oi = 0; oi < sz; oi++, i++)
    {
      *(o + oi) = *(b + i);
    }
  }
  return e;
}


