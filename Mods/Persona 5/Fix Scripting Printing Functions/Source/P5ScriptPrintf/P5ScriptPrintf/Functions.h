#pragma once

#include <types.h>

struct __attribute__ ((packed)) OPD_t
{
    uint32_t Function;
    uint32_t TOC;
};

#define START_BIND_FUNC( ADDRESS ) \
    OPD_t __OPD; \
    __OPD.Function = ADDRESS; \
    __OPD.TOC = 0xD01288;

#define FUNC_PTR( NAME, RET, ... ) \
    ((RET(*)(__VA_ARGS__))(&__OPD))

#define INLINE inline __attribute__((always_inline))

#define BIND_FUNC_1( ADDRESS, RET, NAME, PT1, PN1 ) \
    INLINE RET NAME( PT1 PN1 ) \
    { \
        START_BIND_FUNC( ADDRESS ) \
        return FUNC_PTR( NAME, RET, PT1 )( PN1 ); \
    }

BIND_FUNC_1( 0x1F266C, uint32_t, ScriptInterpreter_GetIntArg, uint32_t, index );
BIND_FUNC_1( 0x1F2768, float, ScriptInterpreter_GetFloatArg, int32_t, index );
BIND_FUNC_1( 0x1F2868, char*, ScriptInterpreter_GetStringArg, int32_t, index );

// fix for , in parameter list while __VA_ARGS__ is empty
#define VA_ARGS(...) , ##__VA_ARGS__

#define printf( format, ... ) \
    { START_BIND_FUNC( 0xAD546C ) FUNC_PTR( printf, int32_t, char*, ... )( format VA_ARGS(__VA_ARGS__) ); } 
