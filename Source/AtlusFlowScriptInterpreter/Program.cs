using System;
using AtlusScriptLib.Common.Registry;
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
    float x = DegreesToRadians( 0 );
    float y = DegreesToRadians( 45 );
    float z = DegreesToRadians( 0 );
    
    PUTS( ""x = %f y = %f z = %f"", x, y, z );


    float quaternionX;
    float quaternionY;
    float quaternionZ;
    float quaternionW;

    CreateQuaternion( x, y, z, out quaternionX, out quaternionY, out quaternionZ, out quaternionW );

    PUTS( ""x = %f y = %f z = %f w = %f"", quaternionX, quaternionY, quaternionZ, quaternionW );
}

// Construct a new Quaternion from given Euler angles in radians. 
// The rotations will get applied in following order:
// 1. around X axis, 2. around Y axis, 3. around Z axis
// Result is stored in quaternionX/Y/Z/W
void CreateQuaternion(float rotationX, float rotationY, float rotationZ, out float quaternionX, out float quaternionY, out float quaternionZ, out float quaternionW )
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


            var compiler = new FlowScriptCompiler( FormatVersion.Version3BigEndian );
            compiler.Library = LibraryLookup.GetLibrary( "p5" );
            compiler.EnableProcedureTracing = false;
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
