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
        private Dictionary<int, int> mIfStatementDepthMap;

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
                //if ( evaluatedProcedure.Procedure.Name == "D_ENCOUNT_NO_GET" )
                //    continue;

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
            mIfStatementDepthMap = new Dictionary<int, int>();
        }

        private bool TryCompositeEvaluatedInstructions( List<FlowScriptEvaluatedStatement> evaluatedStatements, out List<FlowScriptStatement> statements )
        {
            InitializeCompositionState( evaluatedStatements );

            // Insert label declarations, they'll be used to build if statements
            InsertLabelDeclarations();

            // Build the if statement bodies, they rely on the label declarations
            BuildIfStatementMaps();

            // Coagulate variable assignments with declarations if possible
            // This also solves the issue of variable scoping in if statements
            CoagulateVariableDeclarationAssignments();

            // Remove unreferenced labels
            RemoveUnreferencedLabels();

            // Build if statements
            BuildIfStatements();

            // Fittingly remove duped return statements last
            RemoveDuplicateReturnStatements();

            // Convert the evaluated statements to regular statements
            statements = mEvaluatedStatements
                .Select( x => x.Statement )
                .ToList();

            return true;
        }

        private void InsertLabelDeclarations()
        {
            foreach ( var label in mEvaluatedProcedure.Procedure.Labels )
            {
                // Find best index to insert the label at
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

        private void BuildIfStatementMaps()
        {
            // Build if statement bodies
            var evaluatedIfStatements = mEvaluatedStatements.Where( x => x.Statement is FlowScriptIfStatement ).ToList();
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                var falseLabel = evaluatedIfStatement.ReferencedLabel;

                // Extract statements contained in the if statement's body
                var bodyEvaluatedStatements = mEvaluatedStatements
                    .Where( x => x != evaluatedIfStatement && x.InstructionIndex >= evaluatedIfStatement.InstructionIndex && x.InstructionIndex < falseLabel.InstructionIndex )
                    .ToList();

                // We keep the if statements in a map to retain evaluation info until we finally build the if statements
                mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex] = bodyEvaluatedStatements;

                // Detect else if
                var evaluatedGotoStatement = bodyEvaluatedStatements.LastOrDefault();
                if ( evaluatedGotoStatement != null && evaluatedGotoStatement.Statement is FlowScriptGotoStatement )
                {
                    if ( evaluatedGotoStatement.ReferencedLabel.InstructionIndex !=
                         evaluatedGotoStatement.InstructionIndex + 1 )
                    {
                        // Try to detect if-else pattern
                        var elseBodyEvaluatedStatements = mEvaluatedStatements
                            .Where( x => x != evaluatedGotoStatement && x.InstructionIndex >= evaluatedGotoStatement.InstructionIndex && x.InstructionIndex < evaluatedGotoStatement.ReferencedLabel.InstructionIndex )
                            .ToList();

                        if ( elseBodyEvaluatedStatements.Any() )
                            mIfStatementElseBodyMap[evaluatedIfStatement.InstructionIndex] = elseBodyEvaluatedStatements;
                    }
                }

                // Increment depth
                mIfStatementDepthMap[ evaluatedIfStatement.InstructionIndex ] = 0;

                foreach ( var ifStatementBodyMap in mIfStatementBodyMap )
                {
                    if ( ifStatementBodyMap.Value.Contains( evaluatedIfStatement ) )
                    {
                        ++mIfStatementDepthMap[ ifStatementBodyMap.Key ];
                    }
                }

                foreach ( var ifStatementElseBodyMap in mIfStatementElseBodyMap )
                {
                    if ( ifStatementElseBodyMap.Value.Contains( evaluatedIfStatement ) )
                    {
                        ++mIfStatementDepthMap[ifStatementElseBodyMap.Key];
                    }
                }
            }

            // Remove statements in if statement bodies from list of statements
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                var body = mIfStatementBodyMap[ evaluatedIfStatement.InstructionIndex ];
                mIfStatementElseBodyMap.TryGetValue( evaluatedIfStatement.InstructionIndex, out var elseBody );

                body.ForEach( x => mEvaluatedStatements.Remove( x ) );
                if ( elseBody != null )
                    elseBody.ForEach( x => mEvaluatedStatements.Remove( x ) );

                foreach ( var ifStatementBodyMap in mIfStatementBodyMap )
                {
                    if ( ifStatementBodyMap.Value.Contains( evaluatedIfStatement ) )
                    {
                        body.ForEach( x => ifStatementBodyMap.Value.Remove( x ) );
                        if ( elseBody != null )
                            elseBody.ForEach( x => ifStatementBodyMap.Value.Remove( x ) );
                    }
                }

                foreach ( var ifStatementBodyMap in mIfStatementElseBodyMap )
                {
                    if ( ifStatementBodyMap.Value.Contains( evaluatedIfStatement ) )
                    {
                        body.ForEach( x => ifStatementBodyMap.Value.Remove( x ) );
                        if ( elseBody != null )
                            elseBody.ForEach( x => ifStatementBodyMap.Value.Remove( x ) );
                    }
                }

            }

            // Clean up if statement bodies
            foreach ( var evaluatedIfStatement in evaluatedIfStatements )
            {
                var bodyEvaluatedStatements = mIfStatementBodyMap[ evaluatedIfStatement.InstructionIndex ];

                // Remove goto to after if statement inside body if it's right after the if statement body
                var evaluatedGotoStatement = bodyEvaluatedStatements.LastOrDefault();
                if ( evaluatedGotoStatement != null && evaluatedGotoStatement.Statement is FlowScriptGotoStatement )
                {
                    // Likely a single if statement
                    if ( evaluatedGotoStatement.ReferencedLabel.InstructionIndex == evaluatedGotoStatement.InstructionIndex + 1 )
                    {
                        bodyEvaluatedStatements.Remove( evaluatedGotoStatement );

                        /*
                        mEvaluatedStatements.RemoveAll(
                            x => x.ReferencedLabel == evaluatedGotoStatement.ReferencedLabel &&
                                 x.Statement is FlowScriptLabelDeclaration );
                        */
                    }

                    if ( mIfStatementElseBodyMap.TryGetValue( evaluatedIfStatement.InstructionIndex,
                        out var elseBodyEvaluatedStatements ) )
                    {
                        if ( elseBodyEvaluatedStatements.Any() )
                        {
                            bodyEvaluatedStatements.Remove( evaluatedGotoStatement );

                            if ( elseBodyEvaluatedStatements.First().Statement is FlowScriptLabelDeclaration )
                                elseBodyEvaluatedStatements.Remove( elseBodyEvaluatedStatements.First() );

                            if ( elseBodyEvaluatedStatements.Last().Statement is FlowScriptGotoStatement )
                            {
                                var elseBodyGotoStatement = elseBodyEvaluatedStatements.Last();
                                if ( elseBodyGotoStatement.ReferencedLabel.InstructionIndex ==
                                     elseBodyGotoStatement.InstructionIndex + 1 )
                                {
                                    elseBodyEvaluatedStatements.Remove( elseBodyGotoStatement );

                                    /*
                                    mEvaluatedStatements.RemoveAll(
                                        x => x.ReferencedLabel == elseBodyGotoStatement.ReferencedLabel &&
                                             x.Statement is FlowScriptLabelDeclaration );
                                    */
                                }
                            }
                        }
                    }
                }

            }
        }

        private void CoagulateVariableDeclarationAssignments()
        {
            if ( mIfStatementDepthMap.Any( x => x.Key > 20 ) )
            {
                CoagulateVariableDeclarationAssignmentsNonRecursively();
            }
            else
            {
                CoagulateVariableDeclarationAssignmentsRecursively( mEvaluatedStatements, new HashSet<string>() );
            }
        }

        private void CoagulateVariableDeclarationAssignmentsNonRecursively( )
        {
            // Declared variables in the current scope
            var declaredVariables = new HashSet<string>();

            foreach ( var referencedVariable in mEvaluatedProcedure.ReferencedVariables.OrderBy( x => x.InstructionIndex ) )
            {
                int index = referencedVariable.InstructionIndex;
                var identifier = referencedVariable.Identifier;

                // Scope if either the parent or the current scope contains the variable, or if the variable is declared in the evaluated Scope
                if ( declaredVariables.Contains( identifier.Text ) ||
                     !mEvaluatedProcedure.Scope.Variables.TryGetValue( identifier.Text, out var declaration ) )
                    continue;

                // Variable hasn't already been declared
                int evaluatedStatementIndex = mEvaluatedStatements.FindIndex( x => x.InstructionIndex == index );
                if ( evaluatedStatementIndex == -1 )
                {
                    mEvaluatedStatements.Insert( 0,
                        new FlowScriptEvaluatedStatement(
                            declaration, 0, null ) );
                }
                else
                {
                    var evaluatedStatement = mEvaluatedStatements[evaluatedStatementIndex];

                    // Check if the statement is an assignment expression
                    // Which would mean we have an initializer
                    FlowScriptExpression initializer = null;
                    if ( evaluatedStatement.Statement is FlowScriptAssignmentOperator assignment )
                    {
                        // Only match initializers if the target of the operator
                        // Is actually the same identifier
                        if ( assignment.Left == identifier )
                        {
                            initializer = assignment.Right;
                        }
                    }

                    // Coagulate assignment with declaration
                    if ( initializer != null )
                    {
                        declaration.Initializer = initializer;
                        mEvaluatedStatements[evaluatedStatementIndex] = new FlowScriptEvaluatedStatement(
                            declaration, index, null );
                    }
                    else
                    {
                        mEvaluatedStatements.Insert( evaluatedStatementIndex - 1,
                            new FlowScriptEvaluatedStatement(
                                declaration, index - 1, null ) );
                    }
                }

                declaredVariables.Add( identifier.Text );
            }
        }

        private void CoagulateVariableDeclarationAssignmentsRecursively( List<FlowScriptEvaluatedStatement> evaluatedStatements, HashSet<string> parentScopeDeclaredVariables )
        {
            LogInfo( $"Coagulating variable declarations and assignments: {evaluatedStatements.First().InstructionIndex} - {evaluatedStatements.Last().InstructionIndex}" );

            // Declared variables in the current scope
            var declaredVariables = new HashSet<string>();

            // All referenced variable identifiers in statements
            var referencedLocalVariableIdentifiers =
                mEvaluatedProcedure.ReferencedVariables.Where(
                    x => evaluatedStatements.Any( y => x.InstructionIndex == y.InstructionIndex ) );

            // All if statements in statements
            var ifStatements = evaluatedStatements
                .Where( x => x.Statement is FlowScriptIfStatement )
                .ToList();

            foreach ( var variableIdentifierReference in referencedLocalVariableIdentifiers )
            {
                int index = variableIdentifierReference.InstructionIndex;
                var identifier = variableIdentifierReference.Identifier;

                // Scope if either the parent or the current scope contains the variable, or if the variable is declared in the evaluated Scope
                if ( parentScopeDeclaredVariables.Contains( identifier.Text ) ||
                     declaredVariables.Contains( identifier.Text ) ||
                     !mEvaluatedProcedure.Scope.Variables.TryGetValue( identifier.Text, out var declaration ) )
                    continue;

                // Variable hasn't already been declared
                int evaluatedStatementIndex = evaluatedStatements.FindIndex( x => x.InstructionIndex == index );
                var evaluatedStatement = evaluatedStatements[ evaluatedStatementIndex ];

                // Check if the statement is an assignment expression
                // Which would mean we have an initializer
                FlowScriptExpression initializer = null;
                if ( evaluatedStatement.Statement is FlowScriptAssignmentOperator assignment )
                {
                    // Only match initializers if the target of the operator
                    // Is actually the same identifier
                    if ( assignment.Left == identifier )
                    {
                        initializer = assignment.Right;
                    }
                }

                // Find the best insertion index
                int insertionIndex = evaluatedStatementIndex;
                int instructionIndex = index;

                // Check if the variable has been referenced before in an if statement
                foreach ( var evaluatedIfStatement in ifStatements.Where( x => x.InstructionIndex <= index ) )
                {
                    var ifStatementBody = mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex];
                    var referencedLocalVariableIdentifiersInIfStatementBody =
                        mEvaluatedProcedure.ReferencedVariables.Where(
                            x => ifStatementBody.Any( y => x.InstructionIndex == y.InstructionIndex ) );

                    if ( referencedLocalVariableIdentifiersInIfStatementBody.Any(
                        x => x.Identifier.Text == identifier.Text ) )
                    {
                        // The variable was referenced in a previous if statement, so we should insert it before the start of the if statement
                        insertionIndex = evaluatedStatements.IndexOf( evaluatedIfStatement );
                        instructionIndex = evaluatedIfStatement.InstructionIndex - 1;

                        // Edge case
                        if ( instructionIndex < 0 )
                            instructionIndex = 0;

                        break;
                    }

                    if ( mIfStatementElseBodyMap.TryGetValue( evaluatedIfStatement.InstructionIndex,
                        out var ifStatementElseBody ) )
                    {
                        var referencedLocalVariableIdentifiersInIfStatementElseBody =
                            mEvaluatedProcedure.ReferencedVariables.Where(
                                x => ifStatementElseBody.Any( y => x.InstructionIndex == y.InstructionIndex ) );

                        if ( referencedLocalVariableIdentifiersInIfStatementElseBody.Any(
                            x => x.Identifier.Text == identifier.Text ) )
                        {
                            // The variable was referenced in a previous if statement, so we should insert it before the start of the if statement
                            insertionIndex = evaluatedStatements.IndexOf( evaluatedIfStatement );
                            instructionIndex = evaluatedIfStatement.InstructionIndex - 1;

                            // Edge case
                            if ( instructionIndex < 0 )
                                instructionIndex = 0;

                            break;
                        }
                    }
                }

                if ( insertionIndex != evaluatedStatementIndex )
                {
                    // If the insertion index isn't equal to the evaluated statement index
                    // Then that means it was previously referenced in the body of an if statement
                    // So we insert declaration before if statement in which it was used
                    evaluatedStatements.Insert( insertionIndex,
                        new FlowScriptEvaluatedStatement( declaration, instructionIndex, null ) );
                }
                else
                {
                    // If the insertion index is still the same, then that means we probably have a declaration with an assignment
                    // Or maybe we have a reference to an undeclared variable!

                    if ( initializer == null )
                    {
                        // Reference to undeclared variable
                        LogInfo( $"Reference to uninitialized variable! Adding 0 initializer: {declaration}" );
                        initializer = new FlowScriptIntLiteral( 0 ); 
                    }

                    // Coagulate assignment with declaration
                    declaration.Initializer = initializer;
                    evaluatedStatements[evaluatedStatementIndex] = new FlowScriptEvaluatedStatement(
                        declaration, instructionIndex, null );
                }

                declaredVariables.Add( identifier.Text );
            }

            // Merge parent scope with local scope
            foreach ( string declaredVariable in parentScopeDeclaredVariables )
                declaredVariables.Add( declaredVariable );

            foreach ( var ifStatement in ifStatements )
            {
                // Do the same for each if statement
                var body = mIfStatementBodyMap[ifStatement.InstructionIndex];
                CoagulateVariableDeclarationAssignmentsRecursively( body, declaredVariables );

                if ( mIfStatementElseBodyMap.TryGetValue( ifStatement.InstructionIndex, out var elseBody ) )
                    CoagulateVariableDeclarationAssignmentsRecursively( elseBody, declaredVariables );
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

        private void BuildIfStatements()
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

        private void RemoveUnreferencedLabels( )
        {
            foreach ( var evaluatedStatement in mEvaluatedStatements.Where( x => x.Statement is FlowScriptLabelDeclaration ).ToList() )
            {
                if ( !IsLabelReferenced( evaluatedStatement.ReferencedLabel ) )
                    mEvaluatedStatements.Remove( evaluatedStatement );
            }

            foreach ( var body in mIfStatementBodyMap.Values )
            {
                foreach ( var evaluatedStatement in body.Where( x => x.Statement is FlowScriptLabelDeclaration ).ToList() )
                {
                    if ( !IsLabelReferenced( evaluatedStatement.ReferencedLabel ) )
                        body.Remove( evaluatedStatement );
                }        
            }

            foreach ( var body in mIfStatementElseBodyMap.Values )
            {
                foreach ( var evaluatedStatement in body.Where( x => x.Statement is FlowScriptLabelDeclaration ).ToList() )
                {
                    if ( !IsLabelReferenced( evaluatedStatement.ReferencedLabel ) )
                        body.Remove( evaluatedStatement );
                }
            }
        }

        private bool IsLabelReferenced( FlowScriptLabel label )
        {
            foreach ( var evaluatedStatement in mEvaluatedStatements )
            {
                if ( evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is FlowScriptGotoStatement)
                    return true;
            }

            foreach ( var evaluatedStatement in mIfStatementBodyMap.Values.SelectMany( x => x ) )
            {
                if ( evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is FlowScriptGotoStatement )
                    return true;
            }

            foreach ( var evaluatedStatement in mIfStatementElseBodyMap.Values.SelectMany( x => x ) )
            {
                if ( evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is FlowScriptGotoStatement )
                    return true;
            }

            return false;
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
