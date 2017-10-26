using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluationResult
    {
        public FlowScript FlowScript { get; }

        public List<FlowScriptFunctionDeclaration> Functions { get; }

        public FlowScriptEvaluatedScope Scope { get; }

        public List<FlowScriptEvaluatedProcedure> Procedures { get; }

        public Dictionary<FlowScriptStatement, FlowScriptEvaluatedStatement> EvaluatedStatementInfoLookup { get; }

        internal FlowScriptEvaluationResult( FlowScript flowScript, FlowScriptEvaluatedScope scope )
        {
            FlowScript = flowScript;
            Scope = scope;
            Functions = new List<FlowScriptFunctionDeclaration>();
            Procedures = new List<FlowScriptEvaluatedProcedure>();
        }
    }
}