using System;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using AtlusScriptLibrary.FlowScriptLanguage.Disassembler;
using AtlusScriptLibrary.FlowScriptLanguage.Interpreter;


namespace AtlusFlowScriptInterpreter
{
    internal static class Program
    {
        private static void Main( string[] args )
        {
            var source = @"
const int constArray[] = { 1, 2, 3, 4, 5 };     // arrays can be const which allows them to be defined outside of procedures

void Main()
{
    int array[5]; 								// All initialized to zero
    array[0] = 1; 								// array[0] is now 1
    int array2[] = { 1, 2, 3, 4, 5 }; 			// supports initializer lists
    int array3[5] = array;						// array2 references array. no copying done.
    TakesArrayParameter( array3 );	            // array3 is copied due to format limitations.

    int array5[5];
    TakesOutArrayParameter( out array5 );

    global int globalArray[] = { 10, 20, 30, 40, 50 };

    PUTS( ""array[0] = %d"", array[0] ); 
    PUTS( ""array5[0] = %d"", array5[0] );
    PUTS( ""constArray[0] = %d"", constArray[0] );
    PUTS( ""globalArray[0] = %d"", globalArray[0] ); 

    array5 = { 6, 7, 8, 9, 10 };
    PUTS( ""array5[0] = %d"", array5[0] );
}

void TakesArrayParameter(int array[5])
{
    PUTS( ""array[0] = %d"", array[0] );
}

void TakesOutArrayParameter( out int array[5] )
{
    array[0] = 5;
}
";

            var compiler = new FlowScriptCompiler( FormatVersion.Version3BigEndian );
            compiler.Library = LibraryLookup.GetLibrary( "p5" );
            compiler.EnableProcedureTracing = false;
            compiler.AddListener( new ConsoleLogListener( true, LogLevel.All ) );
            if ( !compiler.TryCompile( source, out var script ) )
            {
                Console.WriteLine( "Script failed to compile" );
                return;
            }

            script.ToFile( "test.bf" );

            var dissassembler = new FlowScriptBinaryDisassembler( "test.flowasm" );
            dissassembler.Disassemble( script.ToBinary() );
            dissassembler.Dispose();

            var interpreter = new FlowScriptInterpreter( script );
            interpreter.Run();
        }
    }
}
