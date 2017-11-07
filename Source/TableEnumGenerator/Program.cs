using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusTable;
using AtlusTable.Serialization;
using Tables = AtlusTable.Tables;

namespace TableEnumGenerator
{
    class Program
    {
        static void Main( string[] args )
        {
            var table = TableSerializer.Deserialize< Tables.DigitalDevilSaga.MessageTable >( @"D:\Modding\DDS3\DDS1EN\DDS3\battle\MSG.TBL" );
            WriteEnum( "BattleSkill", "This enum represents the available skills in battle", table.SkillNames );
            WriteEnum( "BattleUnit", "This enum represents the available units in battle", table.UnitNames );
        }

        static void WriteEnum( string enumName, string description, string[] strings )
        {
            var enumValueHashSet = new HashSet< string >();

            using ( var writer = File.CreateText( $"{enumName}.json" ) )
            {
                writer.WriteLine( "{" );
                writer.WriteLine( $@"""Name"": ""{enumName}""," );
                writer.WriteLine( $@"""Description"": ""{description}""," );
                writer.WriteLine( @"""Members"": [" );

                for ( var index = 0; index < strings.Length; index++ )
                {
                    var s = strings[ index ];
                    var enumValueName = s;
                    enumValueName = enumValueName.Replace( " ", "" );
                    enumValueName = enumValueName.Replace( ",", "" );
                    enumValueName = enumValueName.Replace( "_", "" );
                    enumValueName = enumValueName.Replace( "''", "" );
                    enumValueName = enumValueName.Replace( "(", "" );
                    enumValueName = enumValueName.Replace( ")", "" );
                    enumValueName = enumValueName.Replace( ":", "" );
                    enumValueName = enumValueName.Replace( "-", "" );
                    enumValueName = enumValueName.Replace( "&", "And" );
                    enumValueName = enumValueName.Replace( "!", "" );
                    enumValueName = enumValueName.Replace( ".", "" );

                    if ( char.IsDigit( enumValueName[0] ) )
                        enumValueName = "_" + enumValueName;

                    var duplicateEnumValueName = enumValueName;
                    int duplicateCounter = 1;
                    while ( enumValueHashSet.Contains( enumValueName ) )
                        enumValueName = duplicateEnumValueName + duplicateCounter++;

                    enumValueHashSet.Add( enumValueName );

                    writer.WriteLine( "{" );
                    writer.WriteLine( $@"""Name"": ""{enumValueName}""" );
                    writer.WriteLine( $@"""Value"": {index}" );
                    writer.WriteLine( $@"""Description"": ""Generated from table entry: {s}""" );

                    if ( index != strings.Length - 1 )
                        writer.WriteLine( "}," );
                    else
                        writer.WriteLine( "}" );
                }

                writer.WriteLine( "]" );
                writer.WriteLine( "}" );
            }
        }
    }
}
