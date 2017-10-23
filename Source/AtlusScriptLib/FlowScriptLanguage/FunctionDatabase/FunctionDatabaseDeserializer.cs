using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Globalization;

using Newtonsoft.Json;
using AtlusScriptLib.FlowScriptLanguage.Syntax;
#pragma warning disable 649

namespace AtlusScriptLib.FlowScriptLanguage.FunctionDatabase
{
    [SuppressMessage( "ReSharper", "ClassNeverInstantiated.Local" )]
    [SuppressMessage( "ReSharper", "CollectionNeverUpdated.Local" )]
    public class FunctionDatabaseDeserializer
    {
        public static bool TryDeserializeFlowScriptFunctionDatabase( string path, out List<FlowScriptFunctionDeclaration> declarations )
        {
            declarations = new List<FlowScriptFunctionDeclaration>();
            var definitions = JsonConvert.DeserializeObject<List<DatabaseFunctionDefinition>>( File.ReadAllText( path ) );

            foreach ( var definition in definitions )
            {
                if ( !TryParseShort( definition.Index, out short indexValue ) )
                    return false;

                var index = new FlowScriptIntLiteral( indexValue );

                if ( !Enum.TryParse( definition.ReturnType, true, out FlowScriptValueType returnTypeEnum ) )
                    return false;

                var returnType = new FlowScriptTypeIdentifier( returnTypeEnum );
                var identifier = new FlowScriptIdentifier( definition.Name );

                var parameters = new List<FlowScriptParameter>();
                foreach ( var parameter in definition.Parameters )
                {
                    if ( !Enum.TryParse( parameter.Type, true, out FlowScriptValueType parameterTypeEnum ) )
                        return false;

                    var parameterType = new FlowScriptTypeIdentifier( parameterTypeEnum );
                    var parameterIdentifier = new FlowScriptIdentifier( parameter.Name );
                    parameters.Add( new FlowScriptParameter( parameterType, parameterIdentifier ) );
                }

                var declaration = new FlowScriptFunctionDeclaration( index, returnType, identifier, parameters );
                declarations.Add( declaration );
            }

            return true;
        }

        private static bool TryParseShort( string str, out short value )
        {
            if ( str.StartsWith( "0x" ) )
            {
                str = str.Substring( 2 );
                return short.TryParse( str, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value );
            }
            else
            {
                return short.TryParse( str, out value );
            }
        }

        private struct DatabaseFunctionDefinition
        {
            public string Index;
            public string ReturnType;
            public string Name;
            public string Description;
            public List<DatabaseFunctionParameter> Parameters;
        }

        private struct DatabaseFunctionParameter
        {
            public string Type;
            public string Name;
            public string Description;
        }
    }
}
