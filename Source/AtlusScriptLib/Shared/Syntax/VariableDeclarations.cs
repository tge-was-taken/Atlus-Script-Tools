using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public enum VariableDeclarationFlags
    {
        None,
        AccessLocal,
        AccessStatic,
        AccessGlobal,
        TypeInt,
        TypeFloat,
        TypeString
    }

    public class VariableDeclaration : Declaration
    {
        public VariableDeclarationFlags Flags { get; }

        public VariableDeclaration(Identifier identifier, VariableDeclarationFlags flags)
            : base(identifier)
        {
            Flags = flags;
        }

        public override string ToString()
        {
            string flagStr = string.Empty;

            if ((Flags & VariableDeclarationFlags.AccessStatic) == VariableDeclarationFlags.AccessStatic)
                flagStr += " static";

            if ((Flags & VariableDeclarationFlags.TypeInt) == VariableDeclarationFlags.TypeInt)
                flagStr += " int";

            if ((Flags & VariableDeclarationFlags.TypeFloat) == VariableDeclarationFlags.TypeFloat)
                flagStr += " float";

            if ((Flags & VariableDeclarationFlags.TypeString) == VariableDeclarationFlags.TypeString)
                flagStr += " string";

            if (Flags != VariableDeclarationFlags.None)
                return $"var {flagStr} {Identifier}";
            else
                return $"var {Identifier}";
        }
    }

    public class VariableDefinition : VariableDeclaration
    {
        public Expression Initializer { get; }

        public VariableDefinition(Identifier identifier, VariableDeclarationFlags flags, Expression initializer)
            : base(identifier, flags)
        {
            Initializer = initializer;
        }

        public VariableDefinition(Identifier identifier, Expression initializer)
            : base(identifier, VariableDeclarationFlags.None)
        {
            Initializer = initializer;
        }

        public override string ToString()
        {
            string flagStr = string.Empty;

            if ((Flags & VariableDeclarationFlags.AccessStatic) == VariableDeclarationFlags.AccessStatic)
                flagStr += " static";

            if ((Flags & VariableDeclarationFlags.TypeInt) == VariableDeclarationFlags.TypeInt)
                flagStr += " int";

            if ((Flags & VariableDeclarationFlags.TypeFloat) == VariableDeclarationFlags.TypeFloat)
                flagStr += " float";

            if ((Flags & VariableDeclarationFlags.TypeString) == VariableDeclarationFlags.TypeString)
                flagStr += " string";

            if (Flags != VariableDeclarationFlags.None)
                return $"var {flagStr} {Identifier} = {Initializer}";
            else
                return $"var {Identifier} = {Initializer}";
        }
    }
}
