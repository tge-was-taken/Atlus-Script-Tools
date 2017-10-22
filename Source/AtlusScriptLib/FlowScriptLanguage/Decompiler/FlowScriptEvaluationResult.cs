using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluationResult
    {
        public List<FlowScriptFunctionDeclaration> Functions { get; }

        public FlowScriptEvaluatedScope Scope { get; }

        public List<FlowScriptEvaluatedProcedure> Procedures { get; }

        internal FlowScriptEvaluationResult( FlowScriptEvaluatedScope scope )
        {
            Scope = scope;
            Functions = new List<FlowScriptFunctionDeclaration>();
            Procedures = new List<FlowScriptEvaluatedProcedure>();
        }
    }
}