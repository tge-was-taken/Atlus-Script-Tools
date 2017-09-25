using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptDeclarationScanner
    {
        private List<FlowScriptDeclaration> mDeclarations;

        public FlowScriptDeclarationScanner()
        {
        }

        public List<FlowScriptDeclaration> ScanForDeclarations( FlowScriptCompilationUnit compilationUnit )
        {
            mDeclarations = new List<FlowScriptDeclaration>();

            ScanCompilationUnitForDeclarations( compilationUnit );

            return mDeclarations;
        }

        private void ScanCompilationUnitForDeclarations( FlowScriptCompilationUnit compilationUnit )
        {
            ScanImportsForDeclarations( compilationUnit.Imports );
            ScanStatementsForDeclarations( compilationUnit.Statements );
        }

        private void ScanImportsForDeclarations( List<FlowScriptImport> imports )
        {
        }

        private void ScanStatementsForDeclarations( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( statement is FlowScriptDeclaration declaration )
                {
                    mDeclarations.Add( declaration );

                    if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
                    {
                        if ( procedureDeclaration.Body != null )
                            ScanStatementsForDeclarations( procedureDeclaration.Body.Statements );
                    }
                }
                else if ( statement is FlowScriptCompoundStatement compoundStatement )
                {
                    ScanStatementsForDeclarations( compoundStatement );
                }
            }
        }
    }
}
