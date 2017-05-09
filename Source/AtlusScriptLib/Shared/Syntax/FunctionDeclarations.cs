using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public enum FunctionDeclarationFlags
    {
        None,
        ReturnTypeVoid,
        ReturnTypeInt,
        ReturnTypeFloat,
        ReturnTypeString,
        ReturnTypeNoReturn,
    }

    public class FunctionDeclaration : Declaration
    {
        public FunctionDeclarationFlags Flags { get; }

        public FunctionArgumentList ArgumentList { get; }

        public FunctionDeclaration(FunctionDeclarationFlags flags, Identifier identifier, FunctionArgumentList arguments)
            : base(identifier)
        {
            Flags = flags;
            ArgumentList = arguments;
        }

        public FunctionDeclaration(Identifier identifier, FunctionArgumentList arguments)
            : this(FunctionDeclarationFlags.None, identifier, arguments)
        {
        }

        public FunctionDeclaration(Identifier identifier)
            : this(FunctionDeclarationFlags.None, identifier, new FunctionArgumentList())
        {
        }

        public override string ToString()
        {
            string flagStr = string.Empty;

            if ((Flags & FunctionDeclarationFlags.ReturnTypeInt) == FunctionDeclarationFlags.ReturnTypeInt)
                flagStr += " int";

            if ((Flags & FunctionDeclarationFlags.ReturnTypeFloat) == FunctionDeclarationFlags.ReturnTypeFloat)
                flagStr += " float";

            if (Flags != FunctionDeclarationFlags.None)
                return $"func {flagStr} {Identifier}{ArgumentList}";
            else
                return $"func {Identifier}{ArgumentList}";
        }
    }

    public class FunctionDefinition : FunctionDeclaration
    {
        public CompoundStatement Body { get; }

        public FunctionDefinition(Identifier identifier, FunctionDeclarationFlags flags, FunctionArgumentList arguments, CompoundStatement body)
            : base(flags, identifier, arguments)
        {
            Body = body;
        }

        public FunctionDefinition(Identifier identifier, FunctionArgumentList arguments, CompoundStatement body)
            : base(identifier, arguments)
        {
            Body = body;
        }

        public FunctionDefinition(Identifier identifier, CompoundStatement body)
            : base(identifier)
        {
            Body = body;
        }

        public override string ToString()
        {
            string flagStr = string.Empty;

            if ((Flags & FunctionDeclarationFlags.ReturnTypeInt) == FunctionDeclarationFlags.ReturnTypeInt)
                flagStr += " int";

            if ((Flags & FunctionDeclarationFlags.ReturnTypeFloat) == FunctionDeclarationFlags.ReturnTypeFloat)
                flagStr += " float";

            if (Flags != FunctionDeclarationFlags.None)
                return $"func {flagStr} {Identifier}({ArgumentList})\n{Body}\n";
            else
                return $"func {Identifier}({ArgumentList})\n{Body}\n";
        }
    }
}
