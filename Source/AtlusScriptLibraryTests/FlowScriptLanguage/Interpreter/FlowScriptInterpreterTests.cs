using System;
using System.IO;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using AtlusScriptLibrary.FlowScriptLanguage.Interpreter;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibraryTests.FlowScriptLanguage.Interpreter
{
    [ TestClass ]
    public class FlowScriptInterpreterTests
    {
        public string RunTest( FormatVersion version, string library, string source )
        {
            var compiler = new FlowScriptCompiler( version );
            compiler.Library                = LibraryLookup.GetLibrary( library );
            compiler.EnableProcedureTracing = false;
            compiler.AddListener( new DebugLogListener() );
            if ( !compiler.TryCompile( source, out var script ) )
            {
                Console.WriteLine( "Script failed to compile" );
                return null;
            }

            var textOutput  = new StringWriter();
            var interpreter = new FlowScriptInterpreter( script );
            interpreter.TextOutput = textOutput;
            interpreter.Run();
            return textOutput.GetStringBuilder().ToString();
        }

        public void RunTest( FormatVersion version, string library, string source, string expectedOutput )
        {
            var output = RunTest( version, library, source );
            Assert.AreEqual( expectedOutput, output );
        }

        public void RunP5Test( string source, string expectedOutput = "" )
        {
            RunTest( FormatVersion.Version3BigEndian, "p5", source, expectedOutput );
        }

        [ TestMethod ]
        public void compare_int_variable_against_minus_one()
        {
            const string source = @"
void Test() 
{ 
    int foo = -1; 
    if ( foo == -1 ) 
        PUTS( ""Passed"" );
}";
            RunP5Test( source, "Passed\n" );
        }

        [TestMethod]
        public void compare_int_literal_against_minus_one()
        {
            const string source = @"
void Test() 
{ 
    if ( -1 == -1 ) 
        PUTS( ""Passed"" );
}";
            RunP5Test( source, "Passed\n" );
        }

        [ TestMethod ]
        public void test_arrays()
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

    global int globalArray[] = { 10, 20, 30, 40, 50 };

    PUTS( ""array[0] = %d"", array[0] ); 
    PUTS( ""array5[1] = %d"", array5[1] );
    PUTS( ""constArray[0] = %d"", constArray[0] );
    PUTS( ""globalArray[0] = %d"", globalArray[0] ); 

    array5 = { 6, 7, 8, 9, 10 };
    PUTS( ""array5[0] = %d"", array5[0] );
}

void TakesArrayParameter(int array[5])
{
    PUTS( ""array[0] = %d"", array[0] );
}
";

            RunP5Test( source,
                       "array[0] = 1\n" +
                       "array[0] = 1\n" +
                       "array5[1] = 0\n" +
                       "constArray[0] = 1\n" +
                       "globalArray[0] = 10\n" +
                       "array5[0] = 6\n" );
        }

        [TestMethod]
        public void array_out_parameter_assignment()
        {
            var source = @"
void Test()
{
    int array[5];
    TakesOutArrayParameter( out array );

    PUTS( ""array[1] = %d"", array[1] );
}

void TakesOutArrayParameter( out int array[5] )
{
    array[1] = 5;
}";

            RunP5Test( source, "array[1] = 5\n" );
        }

        [ TestMethod ]
        public void can_assign_local_variable_declared_at_root_scope_in_a_method()
        {
            string source =
                @"
int test;

void Main()
{
    test = 1;
    int test2 = test;
}";

            RunP5Test( source );
        }

        [ TestMethod ]
        public void array_initializer_with_one_element()
        {
            string source = @"
const int a[] = { 1 };

void Test()
{
    PUT( a[0] );
}";

            RunP5Test( source, "1\n" );
        }

        [TestMethod]
        public void array_initializer_where_last_element_has_a_comma()
        {
            string source = @"
const int a[] = { 1, 2, };

void Test()
{
    PUT( a[0] );
}";

            RunP5Test( source, "1\n" );
        }

        [ TestMethod ]
        public void array_test2()
        {
            var source = @"
const int a[] = { 1, 2 };
const int b[] = { 3, 4 };

void Test()
{
    PUT( GetArrayValue( 0, 0 ) );
}

int GetArrayValue(int arrayIndex, int elementIndex)
{
    switch ( arrayIndex )
    {
        case 0: return a[ elementIndex ];
        case 1: return b[ elementIndex ];
    }

    return 0;
}";

            RunP5Test( source, "1\n" );
        }

        [ TestMethod ]
        public void goto_to_switch_case_label()
        {
            var source = @"
void Test()
{
    switch ( 0 )
    {
        case 0:
            goto case 1;
            break;

        case 1:
            PUTS( ""Passed"" );
            break;
    }
}
";
            RunP5Test( source, "Passed\n" );
        }

        [TestMethod]
        public void goto_to_default_switch_case_label()
        {
            var source = @"
void Test()
{
    switch ( 0 )
    {
        case 0:
            goto case default;
            break;

        default:
            PUTS( ""Passed"" );
            break;
    }
}
";
            RunP5Test( source, "Passed\n" );
        }

        [TestMethod]
        public void negative_floats()
        {
            var source = @"
void Test()
{
    PUTS(""%f"", -420.69);
}
";

            RunP5Test(source, "-420.69\n");
        }
    }
}
