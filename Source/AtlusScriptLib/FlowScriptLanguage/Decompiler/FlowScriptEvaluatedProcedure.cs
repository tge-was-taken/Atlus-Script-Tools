using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluatedProcedure
    {
        public FlowScriptProcedure Procedure { get; internal set; }

        public FlowScriptEvaluatedScope Scope { get; internal set; }

        public List<FlowScriptEvaluatedStatement> Statements { get; internal set; }

        public FlowScriptValueType ReturnType { get; internal set; }

        public List<FlowScriptParameter> Parameters { get; internal set; }

        public List<FlowScriptEvaluatedIdentifierReference> ReferencedVariables { get; internal set; }

        internal FlowScriptEvaluatedProcedure()
        {
            Statements = new List<FlowScriptEvaluatedStatement>();
            Parameters = new List<FlowScriptParameter>();
            ReferencedVariables = new List<FlowScriptEvaluatedIdentifierReference>();
        }
    }
}