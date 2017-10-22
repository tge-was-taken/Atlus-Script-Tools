using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.FunctionDatabase;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptDecompiler
    {
        private Logger mLogger;
        private FlowScriptEvaluationResult mEvaluatedScript;
        private FlowScriptCompilationUnit mCompilationUnit;
        
        // procedure state
        private FlowScriptEvaluatedProcedure mEvaluatedProcedure;

        // compositing state
        private List<FlowScriptEvaluatedStatement> mOriginalEvaluatedStatements;
        private List<FlowScriptEvaluatedStatement> mEvaluatedStatements;
        private Dictionary<FlowScriptStatement, int> mStatementInstructionIndexLookup;
        private Dictionary<int, List<FlowScriptEvaluatedStatement>> mIfStatementBodyMap;
        private Dictionary<int, List<FlowScriptEvaluatedStatement>> mIfStatementElseBodyMap;

        public IFunctionDatabase FunctionDatabase { get; set; }

        /// <summary>
        /// Initializes a FlowScript decompiler.
        /// </summary>
        /// <param name="version"></param>
        public FlowScriptDecompiler()
        {
            mLogger = new Logger( nameof( FlowScriptDecompiler ) );
        }

        /// <summary>
        /// Adds a decompiler log listener. Use this if you want to see what went wrong during decompilation.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        public bool TryDecompile( FlowScript flowScript, out FlowScriptCompilationUnit compilationUnit )
        {
            if ( !TryDecompileScript( flowScript, out compilationUnit ))
            {
                return false;
            }

            return true;
        }

        // 
        // FlowScript Decompilation
        //
        private void InitializeScriptDecompilationState( FlowScriptEvaluationResult evaluationResult )
        {
            mEvaluatedScript = evaluationResult;
            mCompilationUnit = new FlowScriptCompilationUnit();
        }

        private bool TryDecompileScript( FlowScript flowScript, out FlowScriptCompilationUnit compilationUnit )
        {
            // Evaluate script
            if ( !TryEvaluateScript( flowScript, out var evaluationResult ) )
            {
                LogError( "Failed to evaluate script" );
                compilationUnit = null;
                return false;
            }

            if ( !TryDecompileScriptInternal( evaluationResult, out compilationUnit ) )
            {
                LogError( "Failed to decompile script" );
                compilationUnit = null;
                return false;
            }

            return true;
        }

        private bool TryEvaluateScript( FlowScript flowScript, out FlowScriptEvaluationResult evaluationResult )
        {
            var evaluator = new FlowScriptEvaluator();
            evaluator.FunctionDatabase = FunctionDatabase;
            evaluator.AddListener( new LoggerPassthroughListener( mLogger ) );
            if ( !evaluator.TryEvaluateScript( flowScript, out evaluationResult ) )
            {
                LogError( "Failed to evaluate script" );
                evaluationResult = null;
                return false;
            }

            return true;
        }

        private bool TryDecompileScriptInternal( FlowScriptEvaluationResult evaluationResult, out FlowScriptCompilationUnit compilationUnit )
        {
            // Initialize decompiler
            InitializeScriptDecompilationState( evaluationResult );

            // Build function declarations and add them to AST
            BuildFunctionDeclarationSyntaxNodes();

            // Build script-local variable declarations and add them to AST
            BuildScriptLocalVariableDeclarationSyntaxNodes();

            // Build procedure declarations and add them to AST
            if ( !TryBuildProcedureDeclarationSyntaxNodes() )
            {
                LogError( "Failed to decompile procedure declarations" );
                compilationUnit = null;
                return false;
            }

            compilationUnit = mCompilationUnit;
            return true;
        }

        private void BuildFunctionDeclarationSyntaxNodes( )
        {
            foreach ( var functionDeclaration in mEvaluatedScript.Functions )
                mCompilationUnit.Statements.Add( functionDeclaration );
        }

        private void BuildScriptLocalVariableDeclarationSyntaxNodes( )
        {
            foreach ( var flowScriptVariableDeclaration in mEvaluatedScript.Scope.Variables.Values )
                mCompilationUnit.Statements.Add( flowScriptVariableDeclaration );
        }

        private bool TryBuildProcedureDeclarationSyntaxNodes( )
        {
            // Decompile procedures
            foreach ( var evaluatedProcedure in mEvaluatedScript.Procedures )
            {
                if ( !TryDecompileProcedure( evaluatedProcedure, out var declaration ) )
                {
                    LogError( $"Failed to decompile procedure: { evaluatedProcedure.Procedure.Name }" );
                    return false;
                }

                mCompilationUnit.Statements.Add( declaration );
            }

            return true;
        }

        //
        // Procedure decompilation
        //
        private void InitializeProcedureDecompilationState( FlowScriptEvaluatedProcedure procedure )
        {
            mEvaluatedProcedure = procedure;
        }

        private bool TryDecompileProcedure( FlowScriptEvaluatedProcedure evaluatedProcedure, out FlowScriptProcedureDeclaration declaration )
        {
            InitializeProcedureDecompilationState( evaluatedProcedure );

            if ( !TryCompositeEvaluatedInstructions( evaluatedProcedure.Statements, out var statements ))
            {
                LogError( "Failed to composite evaluated instructions" );
                declaration = null;
                return false;
            }
            
            declaration = new FlowScriptProcedureDeclaration(
                new FlowScriptTypeIdentifier(evaluatedProcedure.ReturnType),
                new FlowScriptIdentifier( FlowScriptValueType.Procedure, evaluatedProcedure.Procedure.Name ),
                evaluatedProcedure.Parameters,
                new FlowScriptCompoundStatement( statements ) );

            return true;
        }

        //
        // Compositing
        //
        private void InitializeCompositionState( List<FlowScriptEvaluatedStatement> evaluatedStatements )
        {
            mOriginalEvaluatedStatements = evaluatedStatements;
            mEvaluatedStatements = mOriginalEvaluatedStatements.ToList();

            // Build lookup
            mStatementInstructionIndexLookup = new Dictionary<FlowScriptStatement, int>( evaluatedStatements.Count );
            foreach ( var evaluatedStatement in evaluatedStatements )
                mStatementInstructionIndexLookup[evaluatedStatement.Statement] = evaluatedStatement.InstructionIndex;

            mIfStatementBodyMap = new Dictionary<int, List<FlowScriptEvaluatedStatement>>();
            mIfStatementElseBodyMap = new Dictionary<int, List<FlowScriptEvaluatedStatement>>();
        }

        private bool TryCompositeEvaluatedInstructions( List<FlowScriptEvaluatedStatement> evaluatedStatements, out List<FlowScriptStatement> statements )
        {
            InitializeCompositionState( evaluatedStatements );

            // Insert label declarations, they'll be used to build if statements
            InsertLabelDeclarations();

            // Build the if statement bodies, they rely on the label declarations
            BuildIfStatementBodyMap();

            //
            CoagulateVariableDeclarationAssignments();

            /*
            // Remove gotos whose labels are one instruction after them
            foreach ( var evaluatedGotoStatement in evaluatedStatements.Where( x => x.SyntaxNode is FlowScriptGotoStatement ).ToList() )
            {
                if ( evaluatedGotoStatement.InstructionIndex + 1 == evaluatedGotoStatement.ReferencedLabel.InstructionIndex )
                    evaluatedStatements.Remove( evaluatedGotoStatement );
            }
            */



            /*
            // Create bodies
            for ( int i = 0; i < evaluatedIfStatements.Count; i++ )
            {
                var evaluatedIfStatement = evaluatedIfStatements[i];           
                var bodyEvaluatedStatements = evaluatedIfStatementBodies[i];
                var ifStatement = ( FlowScriptIfStatement )evaluatedIfStatement.SyntaxNode;
                var falseLabel = evaluatedIfStatement.ReferencedLabel;

                // Remove the statements from the list of evaluated statements as they will be stored in the if statement body instead
                //bodyEvaluatedStatements.ForEach( x => evaluatedStatements.Remove( x ) );

                // Remove false label declaration if it's right after the body
                if ( falseLabel.InstructionIndex == bodyEvaluatedStatements.Last().InstructionIndex + 1 )
                {
                    evaluatedStatements.RemoveAll( x => x.SyntaxNode is FlowScriptLabelDeclaration && x.ReferencedLabel == falseLabel );
                }

                // Remove goto to after if statement inside body if it's right after the if statement body
                if ( bodyEvaluatedStatements.Last().SyntaxNode is FlowScriptGotoStatement )
                {
                    var evaluatedGotoStatement = bodyEvaluatedStatements.Last();

                    // Likely a single if statement
                    if ( evaluatedGotoStatement.ReferencedLabel.InstructionIndex == evaluatedGotoStatement.InstructionIndex + 1 )
                    {
                        bodyEvaluatedStatements.Remove( evaluatedGotoStatement );

                        // Remove label itself as well if nothing references it
                        RemoveIfEndLabelIfNotReferenced( evaluatedStatements, ifStatement, evaluatedGotoStatement.ReferencedLabel );
                        RemoveIfEndLabelIfNotReferenced( bodyEvaluatedStatements, ifStatement, evaluatedGotoStatement.ReferencedLabel );
                    }
                    else
                    {
                        // Try to detect if-else pattern
                        var elseBodyEvaluatedStatements = evaluatedStatements
                            .Where( x => x != evaluatedGotoStatement && x.InstructionIndex >= evaluatedGotoStatement.InstructionIndex && x.InstructionIndex < evaluatedGotoStatement.ReferencedLabel.InstructionIndex )
                            .ToList();

                        if ( elseBodyEvaluatedStatements.Any() )
                        {
                            // Remove goto
                            bodyEvaluatedStatements.Remove( evaluatedGotoStatement );

                            // Remove label if it's not referenced
                            if ( !IsLabelReferenced( evaluatedStatements, evaluatedGotoStatement.ReferencedLabel ) && 
                                !IsLabelReferenced( bodyEvaluatedStatements, evaluatedGotoStatement.ReferencedLabel ) && 
                                !IsLabelReferenced( elseBodyEvaluatedStatements, evaluatedGotoStatement.ReferencedLabel ))
                            {
                                evaluatedStatements.RemoveAll( x => x.SyntaxNode is FlowScriptLabelDeclaration && x.ReferencedLabel == evaluatedGotoStatement.ReferencedLabel );
                            }

                            // Remove the else body statements from the list of evaluated statements as they will be stored in the if statement body instead
                            //elseBodyEvaluatedStatements.ForEach( x => evaluatedStatements.Remove( x ) );

                            ifStatement.ElseBody = new FlowScriptCompoundStatement(
                                elseBodyEvaluatedStatements.Select( x => x.SyntaxNode )
                                .ToList()
                                );
                        }
                    }
                }

                // We grew a body
                ifStatement.Body = new FlowScriptCompoundStatement(
                        bodyEvaluatedStatements.Select( x => x.SyntaxNode )
                        .ToList()
                    );
            }

            // Remove bodies from evaluated statements
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                var ifStatement = ( FlowScriptIfStatement )evaluatedIfStatement.SyntaxNode;
                ifStatement.Body.Statements.ForEach( x => evaluatedStatements.RemoveAll( y => y.SyntaxNode == x ) );

                if ( ifStatement.ElseBody != null )
                {
                    ifStatement.ElseBody.Statements.ForEach( x => evaluatedStatements.RemoveAll( y => y.SyntaxNode == x ) );
                }
            }
            */

            BuildIfStatements();

            // Might be expanded to remove other symbolic values later
            RemoveSymbolicReturnAddress();

            // Fittingly remove duped return statements last
            RemoveDuplicateReturnStatements();

            statements = mEvaluatedStatements.Select( x => x.Statement ).ToList();

            return true;
        }

        private void InsertLabelDeclarations()
        {
            foreach ( var label in mEvaluatedProcedure.Procedure.Labels )
            {
                int insertionIndex = -1;
                int highestIndexBefore = -1;
                int lowestIndexAfter = int.MaxValue;
                for ( int i = 0; i < mEvaluatedStatements.Count; i++ )
                {
                    var statement = mEvaluatedStatements[i];
                    if ( statement.InstructionIndex == label.InstructionIndex )
                    {
                        insertionIndex = i;
                        break;
                    }
                    else if ( statement.InstructionIndex > label.InstructionIndex )
                    {
                        if ( statement.InstructionIndex < lowestIndexAfter )
                        {
                            lowestIndexAfter = statement.InstructionIndex;
                        }
                    }
                    else if ( statement.InstructionIndex < label.InstructionIndex )
                    {
                        if ( statement.InstructionIndex > highestIndexBefore )
                        {
                            highestIndexBefore = statement.InstructionIndex;
                        }
                    }
                }

                if ( insertionIndex == -1 )
                {
                    insertionIndex = lowestIndexAfter;

                    int difference1 = label.InstructionIndex - highestIndexBefore;
                    int difference2 = lowestIndexAfter - label.InstructionIndex;
                    if ( difference1 < difference2 )
                    {
                        insertionIndex = mEvaluatedStatements.FindIndex( x => x.InstructionIndex == highestIndexBefore ) + 1;
                    }
                    else
                    {
                        insertionIndex = mEvaluatedStatements.FindIndex( x => x.InstructionIndex == lowestIndexAfter );
                    }
                }

                // Insert label declaration
                mEvaluatedStatements.Insert( insertionIndex,
                    new FlowScriptEvaluatedStatement(
                        new FlowScriptLabelDeclaration(
                            new FlowScriptIdentifier( FlowScriptValueType.Label, label.Name ) ),
                        label.InstructionIndex,
                        label ) );
            }
        }

        private void BuildIfStatementBodyMap()
        {
            // Build if statement bodies
            var evaluatedIfStatements = mEvaluatedStatements.Where( x => x.Statement is FlowScriptIfStatement ).ToList();
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                var ifStatement = ( FlowScriptIfStatement )evaluatedIfStatement.Statement;
                var falseLabel = evaluatedIfStatement.ReferencedLabel;

                // Extract statements contained in the if statement's body
                var bodyEvaluatedStatements = mEvaluatedStatements
                    .Where( x => x != evaluatedIfStatement && x.InstructionIndex >= evaluatedIfStatement.InstructionIndex && x.InstructionIndex < falseLabel.InstructionIndex )
                    .ToList();

                mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex] = bodyEvaluatedStatements;

                /*
                // We grew a body
                ifStatement.Body = new FlowScriptCompoundStatement(
                    bodyEvaluatedStatements.Select( x => x.SyntaxNode )
                        .ToList()
                );
                */
            }

            // Remove statements in if statement bodies from list of statements
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                /*
                var ifStatement = ( FlowScriptIfStatement )evaluatedIfStatement.SyntaxNode;
                ifStatement.Body.Statements.ForEach( x => mEvaluatedStatements.RemoveAll( y => y.SyntaxNode == x ) );
                */

                var body = mIfStatementBodyMap[ evaluatedIfStatement.InstructionIndex ];
                body.ForEach( x => mEvaluatedStatements.Remove( x ) );
            }
        }

        private void CoagulateVariableDeclarationAssignments()
        {
            CoagulateVariableDeclarationAssignmentsRecursive( mEvaluatedStatements, new HashSet<string>() );
        }

        private void CoagulateVariableDeclarationAssignmentsRecursive( List<FlowScriptEvaluatedStatement> statements, HashSet<string> parentScopeDeclaredVariables )
        {
            var declaredVariables = new HashSet<string>();
            var referencedIdentifiers =
                mEvaluatedProcedure.ReferencedVariables.Where(
                    x => statements.Any( y => x.InstructionIndex == y.InstructionIndex ) );

            var ifStatements = statements.Where( x => x.Statement is FlowScriptIfStatement ).ToList();

            foreach ( var identifierReference in referencedIdentifiers )
            {
                int index = identifierReference.InstructionIndex;
                var identifier = identifierReference.Identifier;

                if ( parentScopeDeclaredVariables.Contains( identifier.Text ) ||
                     declaredVariables.Contains( identifier.Text ) ||
                     !mEvaluatedProcedure.Scope.Variables.TryGetValue( identifier.Text, out var declaration ) )
                    continue;

                // Variable hasn't already been declared
                int identifierReferenceStatementIndex = statements.FindIndex( x => x.InstructionIndex == index );
                var statement = statements[ identifierReferenceStatementIndex ];
                FlowScriptExpression initializer = null;
                if ( statement.Statement is FlowScriptAssignmentOperator assignment )
                {
                    if ( assignment.Left == identifier )
                    {
                        initializer = assignment.Right;
                    }
                }

                int insertionIndex = identifierReferenceStatementIndex;
                int instructionIndex = index;

                // Check if it's been referenced before in an if statement
                foreach ( var evaluatedIfStatement in ifStatements.Where( x => x.InstructionIndex <= index ) )
                {
                    var ifStatementBody = mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex];
                    var referencedIdentifiersInIfStatementBody =
                        mEvaluatedProcedure.ReferencedVariables.Where(
                            x => ifStatementBody.Any( y => x.InstructionIndex == y.InstructionIndex ) );

                    if ( referencedIdentifiersInIfStatementBody.Any( x => x.Identifier.Text == identifier.Text ) )
                    {
                        insertionIndex = statements.IndexOf( evaluatedIfStatement );
                        instructionIndex = evaluatedIfStatement.InstructionIndex - 1;
                        if ( instructionIndex < 0 )
                            instructionIndex = 0;
                        break;
                    }
                }

                if ( insertionIndex != identifierReferenceStatementIndex )
                {
                    // Insert declaration before if statement in which it was used
                    statements.Insert( insertionIndex,
                        new FlowScriptEvaluatedStatement( declaration, instructionIndex, null ) );
                }
                else
                {
                    // Coagulate assignment with declaration
                    declaration.Initializer = initializer;
                    statements[identifierReferenceStatementIndex] = new FlowScriptEvaluatedStatement(
                        declaration, instructionIndex, null );
                }

                declaredVariables.Add( identifier.Text );
            }

            // Merge scopes
            foreach ( string declaredVariable in parentScopeDeclaredVariables )
            {
                declaredVariables.Add( declaredVariable );
            }

            foreach ( var ifStatement in ifStatements )
            {
                var body = mIfStatementBodyMap[ifStatement.InstructionIndex];
                CoagulateVariableDeclarationAssignmentsRecursive( body, declaredVariables );

                if ( mIfStatementElseBodyMap.TryGetValue( ifStatement.InstructionIndex, out var elseBody ) )
                    CoagulateVariableDeclarationAssignmentsRecursive( elseBody, declaredVariables );
            }
        }

        private void RemoveDuplicateReturnStatements()
        {
            var returnStatements = mEvaluatedStatements.Where( x => x.Statement is FlowScriptReturnStatement ).ToList();
            for ( int i = 0; i < returnStatements.Count; i += 2 )
            {
                if ( i + 1 >= returnStatements.Count )
                    break;

                if ( ( returnStatements[i + 1].InstructionIndex - returnStatements[i].InstructionIndex ) == 1 )
                    mEvaluatedStatements.Remove( returnStatements[i] );
            }
        }

        private void RemoveSymbolicReturnAddress()
        {
            foreach ( var evaluatedStatement in mEvaluatedStatements.ToList() )
            {
                if ( evaluatedStatement.InstructionIndex == 0 && evaluatedStatement.Statement is FlowScriptIdentifier identifier )
                {
                    // Skip symbolic return address
                    if ( identifier.Text == "<>__ReturnAddress" )
                    {
                        mEvaluatedStatements.Remove( evaluatedStatement );
                    }
                }
            }
        }

        private void BuildIfStatements( )
        {
            foreach ( var evaluatedStatement in mOriginalEvaluatedStatements.Where( x => x.Statement is FlowScriptIfStatement ) )
            {
                var ifStatement = (FlowScriptIfStatement) evaluatedStatement.Statement;

                var body = mIfStatementBodyMap[ evaluatedStatement.InstructionIndex ];
                ifStatement.Body = new FlowScriptCompoundStatement( body.Select( x => x.Statement ).ToList() );

                if ( mIfStatementElseBodyMap.TryGetValue( evaluatedStatement.InstructionIndex, out var elseBody ) )
                    ifStatement.ElseBody = new FlowScriptCompoundStatement( elseBody.Select( x => x.Statement ).ToList() );
            }
        }

        private bool IsLabelReferenced( List<FlowScriptEvaluatedStatement> evaluatedStatements, FlowScriptLabel label )
        {
            return evaluatedStatements.Any( x => !(x.Statement is FlowScriptLabelDeclaration) && x.ReferencedLabel == label );
        }

        private void RemoveIfEndLabelIfNotReferenced( List<FlowScriptEvaluatedStatement> evaluatedStatements, FlowScriptIfStatement ifStatement, FlowScriptLabel label )
        {
            var evaluatedLabelDeclaration = evaluatedStatements
                            .SingleOrDefault( x => x.InstructionIndex == label.InstructionIndex && x.Statement is FlowScriptLabelDeclaration );

            if ( evaluatedLabelDeclaration != null )
            {
                if ( !evaluatedStatements.Where( x => x != evaluatedLabelDeclaration && x.Statement != ifStatement && x.ReferencedLabel == evaluatedLabelDeclaration.ReferencedLabel ).Any() )
                    evaluatedStatements.Remove( evaluatedLabelDeclaration );
            }
        }

        //
        // Logging
        //
        private void LogInfo( string message )
        {
            mLogger.Info( $"            {message}" );
        }

        private void LogError( string message )
        {
            mLogger.Error( $"            {message}" );

            if ( Debugger.IsAttached )
            {
                Debugger.Break();
            }
        }
    }
}
