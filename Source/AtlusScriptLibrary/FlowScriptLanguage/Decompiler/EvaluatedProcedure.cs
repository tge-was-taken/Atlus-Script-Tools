using System.Collections.Generic;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class EvaluatedProcedure
    {
        public Procedure Procedure { get; internal set; }

        public EvaluatedScope Scope { get; internal set; }

        public List<EvaluatedStatement> Statements { get; internal set; }

        public ValueKind ReturnKind { get; internal set; }

        public List<Parameter> Parameters { get; internal set; }

        public List<EvaluatedIdentifierReference> ReferencedVariables { get; internal set; }

        internal EvaluatedProcedure()
        {
            Statements = new List<EvaluatedStatement>();
            Parameters = new List<Parameter>();
            ReferencedVariables = new List<EvaluatedIdentifierReference>();
        }
    }
}