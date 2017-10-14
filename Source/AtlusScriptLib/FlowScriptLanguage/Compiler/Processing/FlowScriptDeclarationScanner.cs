using System.Collections.Generic;

using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler.Processing
{
    public class FlowScriptDeclarationScanner
    {
        private List<FlowScriptDeclaration> mDeclarations;

        public FlowScriptDeclarationScanner()
        {
        }

        public List<FlowScriptDeclaration> Scan( FlowScriptCompilationUnit compilationUnit )
        {
            mDeclarations = new List<FlowScriptDeclaration>();

            ScanCompilationUnit( compilationUnit );

            return mDeclarations;
        }

        public List<FlowScriptDeclaration> Scan( IEnumerable<FlowScriptStatement> statements )
        {
            mDeclarations = new List<FlowScriptDeclaration>();

            ScanStatements( statements );

            return mDeclarations;
        }

        private void ScanCompilationUnit( FlowScriptCompilationUnit compilationUnit )
        {
            ScanImports( compilationUnit.Imports );
            ScanStatements( compilationUnit.Statements );
        }

        private void ScanImports( List<FlowScriptImport> imports )
        {
        }

        private void ScanStatements( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( statement is FlowScriptCompoundStatement compoundStatement )
                {
                    ScanStatements( compoundStatement );
                }
                else if ( statement is FlowScriptDeclaration declaration )
                {
                    mDeclarations.Add( declaration );

                    if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
                    {
                        if ( procedureDeclaration.Body != null )
                            ScanStatements( procedureDeclaration.Body.Statements );
                    }
                }
                else if ( statement is FlowScriptIfStatement ifStatement )
                {
                    ScanStatements( ifStatement.Body );
                    ScanStatements( ifStatement.ElseStatements );
                }
            }
        }
    }
}
