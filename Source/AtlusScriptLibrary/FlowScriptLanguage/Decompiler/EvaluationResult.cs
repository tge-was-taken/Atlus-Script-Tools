using System.Collections.Generic;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class EvaluationResult
    {
        public FlowScript FlowScript { get; }

        public List<FunctionDeclaration> Functions { get; }

        public EvaluatedScope Scope { get; }

        public List<EvaluatedProcedure> Procedures { get; }

        public Dictionary<Statement, EvaluatedStatement> EvaluatedStatementInfoLookup { get; }

        internal EvaluationResult( FlowScript flowScript, EvaluatedScope scope )
        {
            FlowScript = flowScript;
            Scope = scope;
            Functions = new List<FunctionDeclaration>();
            Procedures = new List<EvaluatedProcedure>();
        }
    }
}