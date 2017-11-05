using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Antlr4.Runtime;
using AtlusScriptLib.Common.Registry;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser.Grammar;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Processing;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptEnumDeclaration : FlowScriptDeclaration
    {
        public List<FlowScriptEnumValueDeclaration> Values { get; set; }

        public FlowScriptEnumDeclaration() : base( FlowScriptDeclarationType.Enum )
        {
            Values = new List< FlowScriptEnumValueDeclaration >();
        }

        public FlowScriptEnumDeclaration( FlowScriptIdentifier identifier ) : base( FlowScriptDeclarationType.Enum, identifier )
        {
            Values = new List<FlowScriptEnumValueDeclaration>();
        }

        public override string ToString()
        {
            return $"enum {Identifier} {{ ... }}";
        }

        public static FlowScriptEnumDeclaration FromLibraryEnum( FlowScriptLibraryEnum libraryEnum )
        {
            var enumDeclaration = new FlowScriptEnumDeclaration(
                new FlowScriptIdentifier( FlowScriptValueType.Type, libraryEnum.Name ) );

            foreach ( var libraryEnumMember in libraryEnum.Members )
            {
                var valueDeclaration = new FlowScriptEnumValueDeclaration(
                    new FlowScriptIdentifier( FlowScriptValueType.Unresolved, libraryEnumMember.Name ),
                    FlowScriptExpression.FromText( libraryEnumMember.Value )
                );

                enumDeclaration.Values.Add( valueDeclaration );
            }

            return enumDeclaration;
        }
    }
}
