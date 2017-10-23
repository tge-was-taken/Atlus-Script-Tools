using System;
using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.FunctionDatabase
{
    public interface IFunctionDatabase
    {
        List<FlowScriptFunctionDeclaration> Functions { get; }
    }

    public class Persona5FunctionDatabase : IFunctionDatabase
    {
        private static Persona5FunctionDatabase mInstance;

        public static Persona5FunctionDatabase Instance
        {
            get
            {
                if ( mInstance == null )
                {
                    mInstance = new Persona5FunctionDatabase();
                }

                return mInstance;
            }
        }

        public List<FlowScriptFunctionDeclaration> Functions { get; }

        private Persona5FunctionDatabase()
        {
            if ( !FunctionDatabaseDeserializer.TryDeserializeFlowScriptFunctionDatabase( "FlowScriptLanguage\\FunctionDatabase\\Persona5FunctionDatabase.json", out var functions ) )
            {
                throw new Exception( "Failed to deserialize Persona 5 function database" );
            }

            Functions = functions;
        }
    }
}
