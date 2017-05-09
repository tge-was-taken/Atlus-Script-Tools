using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public abstract class Expression : Statement
    {
    }

    public class Identifier : Expression
    {
        public string Name { get; }

        public Identifier(string name)
        {
            Name = name;
        }

        public override string ToString()
        {
            return $"{Name}";
        }
    }

    public class FunctionCallOperator : Expression, IOperator
    {
        public int Precedence => 1;

        public Identifier Identifier { get; }

        public FunctionArgumentList ArgumentList { get; }

        public FunctionCallOperator(Identifier identifier, FunctionArgumentList argumentList)
        {
            Identifier = identifier;
            ArgumentList = argumentList;
        }

        public FunctionCallOperator(Identifier identifier)
        {
            Identifier = identifier;
            ArgumentList = new FunctionArgumentList();
        }

        public override string ToString()
        {
            return $"{Identifier}{ArgumentList}";
        }
    }
}
