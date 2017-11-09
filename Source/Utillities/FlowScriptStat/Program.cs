using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Registry;
using AtlusScriptLib.FlowScriptLanguage;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace FlowScriptStat
{
    class Program
    {
        static void Main( string[] args )
        {
            var parser = new FlowScriptCompilationUnitParser();
            var script = parser.Parse( File.OpenRead( @"D:\Modding\DDS3\DDS1\DDS3\battle\AICALC.TBL_AI.bf.flow" ) );
            var calls = FlowScriptSyntaxNodeCollector< FlowScriptCallOperator >.Collect( script );
            var bitIds = new Dictionary< int, int >();
            foreach ( var call in calls )
            {
                if ( call.Identifier.Text.StartsWith( "BIT" ) )
                {
                    int id = ( ( FlowScriptIntLiteral )call.Arguments[0] ).Value;

                    if ( !bitIds.ContainsKey( id ) )
                        bitIds.Add( id, 1 );
                    else
                        ++bitIds[ id ];
                }
            }

            using ( var writer = File.CreateText( "output_dds.txt" ) )
            {
                foreach ( int i in bitIds.Keys.OrderByDescending( x => x ) )
                {
                    writer.WriteLine( $"bit {i}\t\tx{bitIds[i]}" );
                }
            }
        }
    }
}
