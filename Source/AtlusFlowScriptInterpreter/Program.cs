using System;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.Common.Libraries;
using AtlusScriptLib.FlowScriptLanguage;
using AtlusScriptLib.FlowScriptLanguage.Compiler;
using AtlusScriptLib.FlowScriptLanguage.Disassembler;
using AtlusScriptLib.FlowScriptLanguage.Interpreter;


namespace AtlusFlowScriptInterpreter
{
    internal static class Program
    {
        private static void Main( string[] args )
        {
            var source = @"
void Main()
{
    float x = DegreesToRadians( 0 );
    float y = DegreesToRadians( 45 );
    float z = DegreesToRadians( 0 );
    
    PUTS( ""x = %f y = %f z = %f"", x, y, z );

    CreateQuaternion( x, y, z );

    PUTS( ""x = %f y = %f z = %f w = %f"", quaternionX, quaternionY, quaternionZ, quaternionW );
}

float quaternionX;
float quaternionY;
float quaternionZ;
float quaternionW;

// Construct a new Quaternion from given Euler angles in radians. 
// The rotations will get applied in following order:
// 1. around X axis, 2. around Y axis, 3. around Z axis
// Result is stored in quaternionX/Y/Z/W
void CreateQuaternion(float rotationX, float rotationY, float rotationZ)
{
    rotationX *= 0.5f;
    rotationY *= 0.5f;
    rotationZ *= 0.5f;

    float c1 = COS(rotationX);
    float c2 = COS(rotationY);
    float c3 = COS(rotationZ);
    float s1 = SIN(rotationX);
    float s2 = SIN(rotationY);
    float s3 = SIN(rotationZ);

    quaternionW = c1 * c2 * c3 - s1 * s2 * s3;
    quaternionX = s1 * c2 * c3 + c1 * s2 * s3;
    quaternionY = c1 * s2 * c3 - s1 * c2 * s3;
    quaternionZ = c1 * c2 * s3 + s1 * s2 * c3;
}

const float PI = 3.14159265358979323846f;
float DegreesToRadians( float degrees )
{
    return degrees * PI / 180f;
}
";

            source = @"
void Main()
{
    float qX;
    float qY;
    float qZ;
    float qW;
    QuatFromEulerDegrees( 0, 45, 0, out qX, out qY, out qZ, out qW );

    PUTS( ""x = %f y = %f z = %f w = %f"", qX, qY, qZ, qW );
}

void QuatFromEulerDegrees( float x, float y, float z, out float qX, out float qY, out float qZ, out float qW )
{
	x = DegreesToRadians( x );
	y = DegreesToRadians( y );
	z = DegreesToRadians( z );
	
	QuatFromEuler( x, y, z, out qX, out qY, out qZ, out qW );
}

void QuatFromEuler( float x, float y, float z, out float qX, out float qY, out float qZ, out float qW )
{
    x *= 0.5f;
    y *= 0.5f;
    z *= 0.5f;

    float c1 = COS( x );
    float c2 = COS( y );
    float c3 = COS( z );
    float s1 = SIN( x );
    float s2 = SIN( y );
    float s3 = SIN( z );

    qW = c1 * c2 * c3 - s1 * s2 * s3;
    qX = s1 * c2 * c3 + c1 * s2 * s3;
    qY = c1 * s2 * c3 - s1 * c2 * s3;
    qZ = c1 * c2 * s3 + s1 * s2 * c3;
}

const float PI = 3.14159265358979323846f;
float DegreesToRadians( float degrees )
{
    return degrees * PI / 180f;
}
";
//            source = @"
//void Main()
//{
//    int test = 69;

//    Test( 0, out test );

//    if ( test == 1 )
//    {
//        PUTS( ""Success!!"" );
//    }
//}

//void Test( int a, out int test )
//{
//    test = 1;
//}";

            source = @"
void Main()
{
    int x = 2;
    int n = 4;
    PUTS( ""Pow( %d, %d ) = %d"", x, n, Pow( x, n ) );
}

int Pow( int x, int n )
{
    int i; /* Variable used in loop counter */
    int number = 1;

    for ( i = 0; i < n; ++i )
        number *= x;

    return number;
}";


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
