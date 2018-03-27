using System.Collections.Generic;
using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class EnumDeclaration : Declaration
    {
        public List<EnumValueDeclaration> Values { get; set; }

        public EnumDeclaration() : base( DeclarationType.Enum )
        {
            Values = new List< EnumValueDeclaration >();
        }

        public EnumDeclaration( Identifier identifier ) : base( DeclarationType.Enum, identifier )
        {
            Values = new List<EnumValueDeclaration>();
        }

        public override string ToString()
        {
            return $"enum {Identifier} {{ ... }}";
        }

        public static EnumDeclaration FromLibraryEnum( FlowScriptModuleEnum libraryEnum )
        {
            var enumDeclaration = new EnumDeclaration(
                new Identifier( ValueKind.Type, libraryEnum.Name ) );

            foreach ( var libraryEnumMember in libraryEnum.Members )
            {
                var valueDeclaration = new EnumValueDeclaration(
                    new Identifier( ValueKind.Unresolved, libraryEnumMember.Name ),
                    Expression.FromText( libraryEnumMember.Value )
                );

                enumDeclaration.Values.Add( valueDeclaration );
            }

            return enumDeclaration;
        }
    }
}
