
#include "OccupyNonVolatileRegisters.h"
#include "Functions.h" 
#include "ScriptInterpreter.h"

#define ScriptInterpreter (*((ScriptInterpreter**)0xD59BFC))
#define NewLineChar ((char*)0xB91820)

int main()
{
    //bool putNewLine = true;
    char* format = ScriptInterpreter_GetStringArg( 0 );
    uint32_t scriptArgIndex = 1;

    void* args[10];
    //bool argIsFloat[10] = {};
    int argCount = 0;

    //if ( *format == '\\' )
    //{
    //    char next = *( format + 1 );
    //    if ( next != 0 && next == 'n' && *( format + 2 ) == 0 ) // single \n
    //        putNewLine = false;
    //}

    char* curFormat = format;
    for (; *curFormat != 0; ++curFormat )
    {
        char c = *curFormat;

        if ( c == '%' )
        {
            char next = *( ++curFormat );
            if ( next == 0 )
                break;

            switch ( next )
            {
            case 'c':
            case 's':
                args[ argCount++ ] = reinterpret_cast<void*>( ScriptInterpreter_GetStringArg( scriptArgIndex++ ) );
                break;

            case 'd':
            case 'i':
            case 'o':
            case 'x':
            case 'X':
            case 'u':
                args[ argCount++ ] = reinterpret_cast<void*>( ScriptInterpreter_GetIntArg( scriptArgIndex++ ) );
                break;

            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'a':
            case 'A':
            case 'g':
            case 'G':
                //double arg = static_cast<double>( ScriptInterpreter_GetFloatArg( scriptArgIndex++ ) );
                //args[ argCount ] = reinterpret_cast<void*>( &arg );
                //argIsFloat[ argCount ] = true;
                ++scriptArgIndex;
                ++argCount;
                break;
            }
        }
    }

    switch ( argCount )
    {
    case 0: printf( format ); break;
    case 1: printf( format, args[0]); break;
    case 2: printf( format, args[0], args[1]); break;
    case 3: printf( format, args[0], args[1], args[2]); break;
    case 4: printf( format, args[0], args[1], args[2], args[3]); break;
    case 5: printf( format, args[0], args[1], args[2], args[3], args[4]); break;
    //case 6: printf( format, args[0], args[1], args[2], args[3], args[4], args[5]); break;
    //case 7: printf( format, args[0], args[1], args[2], args[3], args[4], args[5], args[6]); break;
    //case 8: printf( format, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); break;
    //case 9: printf( format, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]); break;
    //case 10: printf( format, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]); break;
    }

    //if ( putNewLine )
    //    printf( sNewLineChar );
    printf( NewLineChar );

    ScriptInterpreter->mNumStackValues -= argCount;

    return 1;
}