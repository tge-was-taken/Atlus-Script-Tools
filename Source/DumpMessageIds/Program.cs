using System;
using System.IO;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.Compiler;

namespace DumpMessageIds
{
    class Program
    {
        static void Main( string[] args )
        {
            if ( args.Length == 0 )
            {
                Console.WriteLine( $"Missing filename" );
                return;
            }

            MessageScript msg = null;
            var filePath = args[ 0 ];
            if ( filePath.EndsWith( "bf", StringComparison.InvariantCultureIgnoreCase ) )
            {
                msg = FlowScript.FromFile( filePath ).MessageScript;
            }
            else if ( filePath.EndsWith( "bmd" ) )
            {
                msg = MessageScript.FromFile( args[0] );
            }
            else if ( filePath.EndsWith( "msg" ) )
            {
                var msgCompiler = new MessageScriptCompiler( AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1 );
                msg = msgCompiler.Compile( File.OpenText( filePath ) );
            }
            else
            {
                Console.WriteLine( "Can't detect input type (unknown extension)" );
                return;
            }

            using ( var writer = File.CreateText( $"{Path.GetFileNameWithoutExtension( args[ 0 ] )}_ids.txt" ) )
            {
                for ( var i = 0; i < msg.Dialogs.Count; i++ )
                {
                    var dialog = msg.Dialogs[ i ];
                    writer.WriteLine( $"{i}\t\t{dialog.Name}" );
                }
            }
        }
    }
}
