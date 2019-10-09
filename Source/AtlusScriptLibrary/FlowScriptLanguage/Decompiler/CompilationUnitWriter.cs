using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class CompilationUnitWriter : SyntaxNodeVisitor
    {
        public void Write( CompilationUnit compilationUnit, string path )
        {
            using ( var writingVisitor = new WriterVisitor( FileUtils.CreateText( path ) ) )
            {
                writingVisitor.Visit( compilationUnit );
            }
        }

        public void Write( CompilationUnit compilationUnit, TextWriter writer )
        {
            using ( var writingVisitor = new WriterVisitor( writer, false ) )
            {
                writingVisitor.Visit( compilationUnit );
            }
        }

        private class WriterVisitor : SyntaxNodeVisitor, IDisposable
        {
            private readonly TextWriter mWriter;
            private int mTabLevel;
            private bool mInsideLine;
            private ProcedureDeclaration mProcedure;
            private readonly bool mOwnsWriter;

            private readonly Stack<bool> mSuppressIfStatementNewLine;
            private readonly Stack<bool> mSuppressCompoundStatementNewline;

            public WriterVisitor( TextWriter writer, bool ownsWriter = true )
            {
                mOwnsWriter = ownsWriter;
                mWriter = writer;
                mSuppressIfStatementNewLine = new Stack< bool >();
                mSuppressCompoundStatementNewline = new Stack< bool >();
            }

            public override void Visit( Import import )
            {
                WriteImport( import );
            }

            // Unimplemented
            public override void Visit( EnumDeclaration enumDeclaration )
            {
                WriteWithSeperator( "enum" );
                Visit( enumDeclaration.Identifier );

                WriteNewLine();
                WriteLine( "{" );
                IncreaseIndentation();

                for ( var i = 0; i < enumDeclaration.Values.Count; i++ )
                {
                    var enumValueDeclaration = enumDeclaration.Values[ i ];
                    Visit( enumValueDeclaration );
                    if ( i != enumDeclaration.Values.Count - 1 )
                        WriteLine( "," );
                }

                DecreaseIndentation();
                WriteNewLine();
                WriteLine( "}" );
            }

            public override void Visit( EnumValueDeclaration enumValueDeclaration )
            {
                Visit( enumValueDeclaration.Identifier );
                Write( " = " );
                Visit( enumValueDeclaration.Value );
            }

            public override void Visit( MemberAccessExpression memberAccessExpression )
            {
                Visit( memberAccessExpression.Operand );
                Write( "." );
                Visit( memberAccessExpression.Member );
            }

            public override void Visit( SwitchStatement switchStatement )
            {
                WriteWithSeperator( "switch" );
                WriteOpenParenthesis();
                Visit( switchStatement.SwitchOn );
                WriteCloseParenthesis();

                WriteNewLine();
                WriteIndentedLine( "{" );

                foreach ( var label in switchStatement.Labels )
                {
                    Visit( label );
                }

                WriteNewLine();
                WriteIndentedLine( "}" );
                WriteNewLine();
            }

            // Statements
            public override void Visit( CompilationUnit compilationUnit )
            {
                // Write header comments
                WriteNewLine();
                WriteComment( "" );
                WriteComment( "FlowScript decompiled by AtlusScriptLib by TGE (2017)" );
                WriteComment( "In the unfortunate case of any bugs, please report them back to me." );
                WriteComment( "" );
                WriteNewLine();

                if ( compilationUnit.Imports.Count > 0 )
                {
                    // Write import block comments
                    WriteNewLine();
                    WriteComment( "" );
                    WriteComment( "Imports" );
                    WriteComment( "" );
                    WriteNewLine();

                    // Write each import
                    foreach ( var import in compilationUnit.Imports )
                    {
                        Visit( import );
                    }
                }

                bool seenFirstFunction = false;
                bool seenFirstVariableDeclaration = false;
                bool seenFirstProcedure = false;
                foreach ( var statement in compilationUnit.Declarations )
                {
                    // Write fancy comments for declaration blocks
                    if ( !seenFirstFunction && statement is FunctionDeclaration )
                    {
                        WriteNewLine();
                        WriteComment( "" );
                        WriteComment( "Function prototypes" );
                        WriteComment( "" );
                        WriteNewLine();
                        seenFirstFunction = true;
                    }

                    if ( !seenFirstVariableDeclaration && statement is VariableDeclaration )
                    {
                        WriteNewLine();
                        WriteComment( "" );
                        WriteComment( "Script-level variable definitions" );
                        WriteComment( "" );
                        WriteNewLine();
                        seenFirstVariableDeclaration = true;
                    }

                    if ( !seenFirstProcedure && statement is ProcedureDeclaration )
                    {
                        WriteNewLine();
                        WriteComment( "" );
                        WriteComment( "Procedure declarations" );
                        WriteComment( "" );
                        seenFirstProcedure = true;
                    }

                    // Write the statement
                    Visit( statement );

                    // Write the semicolon, but not for procedure declaration because it's ugly
                    if ( !( statement is ProcedureDeclaration ) )
                    {
                        WriteStatementEnd();
                    }
                }
            }

            public override void Visit( ProcedureDeclaration procedureDeclaration )
            {
                mProcedure = procedureDeclaration;

                WriteNewLine();
                Visit( procedureDeclaration.ReturnType );
                Write( " " );
                Visit( procedureDeclaration.Identifier );
                WriteParameters( procedureDeclaration.Parameters );
                if ( procedureDeclaration.Body == null )
                    WriteStatementEnd();
                else
                    Visit( procedureDeclaration.Body );
            }

            public override void Visit( FunctionDeclaration functionDeclaration )
            {
                Write( "function" );
                WriteOpenParenthesis();
                WriteHexIntegerLiteral( functionDeclaration.Index.Value );
                WriteCloseParenthesis();
                Write( " " );
                Visit( functionDeclaration.ReturnType );
                Write( " " );
                Visit( functionDeclaration.Identifier );
                WriteParameters( functionDeclaration.Parameters );
            }

            public override void Visit( VariableDeclaration variableDeclaration )
            {
                if ( variableDeclaration.Modifier.Kind != VariableModifierKind.Local )
                {
                    Write( KeywordDictionary.ModifierTypeToKeyword[variableDeclaration.Modifier.Kind] );
                    if ( variableDeclaration.Modifier.Index != null )
                    {
                        WriteOpenParenthesis();
                        WriteIntegerLiteral( variableDeclaration.Modifier.Index );
                        WriteCloseParenthesis();
                    }

                    Write( " " );
                    Visit( variableDeclaration.Type );
                    Write( " " );
                    Visit( variableDeclaration.Identifier );
                }
                else
                {
                    Visit( variableDeclaration.Type );
                    Write( " " );
                    Visit( variableDeclaration.Identifier );
                }

                if ( variableDeclaration.Initializer != null )
                {
                    Write( " = " );
                    Visit( variableDeclaration.Initializer );
                }
            }

            public override void Visit( Statement statement )
            {
                if ( !( statement is ReturnStatement ) )
                    WriteIndentation();

                base.Visit( statement );

                if ( !( statement is CompoundStatement ) &&
                     !( statement is ForStatement ) &&
                     !( statement is IfStatement ) &&
                     !( statement is SwitchStatement ) &&
                     !( statement is WhileStatement ) &&
                     !( statement is ReturnStatement ) &&
                     !( statement is LabelDeclaration ) &&
                     !( statement is ProcedureDeclaration ) )
                {
                    WriteStatementEnd();
                }
            }

            public override void Visit( CompoundStatement compoundStatement )
            {
                bool suppressNewLine = mSuppressCompoundStatementNewline.Count != 0 && mSuppressCompoundStatementNewline.Pop();

                if ( mInsideLine )
                    WriteNewLine();

                WriteIndentedLine( "{" );

                IncreaseIndentation();
                base.Visit( compoundStatement );
                DecreaseIndentation();

                if ( mTabLevel != 0 && mInsideLine )
                    WriteNewLine();

                WriteIndentedLine( "}" );

                if ( !suppressNewLine )
                    WriteNewLine();
            }

            public override void Visit( BreakStatement statement )
            {
                Write( "break" );
            }

            public override void Visit( ContinueStatement statement )
            {
                Write( "continue" );
            }

            public override void Visit( ReturnStatement statement )
            {
                if ( statement.Value == null )
                {
                    if ( statement != mProcedure.Body.Last() )
                    {
                        WriteIndented( "return" );
                        WriteStatementEnd();
                    }
                }
                else
                {
                    WriteIndented( "return" );
                    Visit( statement.Value );
                    WriteStatementEnd();
                }
            }

            public override void Visit( ForStatement forStatement )
            {
                WriteNewLineAndIndent();
                WriteWithSeperator( "for" );
                WriteOpenParenthesis();
                Visit( forStatement.Initializer );
                Write( "; " );
                Visit( forStatement.Condition );
                Write( "; " );
                Visit( forStatement.AfterLoop );
                WriteCloseParenthesis();
                Visit( forStatement.Body );
            }

            public override void Visit( GotoStatement gotoStatement )
            {
                WriteWithSeperator( "goto" );
                Visit( gotoStatement.Label );
            }

            public override void Visit( IfStatement ifStatement )
            {
                if ( !(mSuppressIfStatementNewLine.Count != 0 && mSuppressIfStatementNewLine.Pop() ) )
                    WriteNewLineAndIndent();

                // Write 'if ( <cond> )
                WriteWithSeperator( "if" );
                WriteOpenParenthesis();
                Visit( ifStatement.Condition );
                WriteCloseParenthesis();

                if ( ifStatement.ElseBody == null )
                {
                    // Write body
                    mSuppressCompoundStatementNewline.Push( false );
                    mSuppressIfStatementNewLine.Push( false );
                    Visit( ifStatement.Body );
                }
                else
                {
                    // Write body
                    mSuppressCompoundStatementNewline.Push( true );
                    Visit( ifStatement.Body );

                    // Write 'else'
                    WriteIndentation();
                    WriteWithSeperator( "else" );

                    if ( ifStatement.ElseBody.Statements.Count > 0 &&
                         ifStatement.ElseBody.Statements[ 0 ] is IfStatement )
                    {
                        // Write else if { }, instead of else { if { } }
                        mSuppressIfStatementNewLine.Push( true );
                        Visit( (IfStatement) ifStatement.ElseBody.Statements[ 0 ] );
                        for ( int i = 1; i < ifStatement.ElseBody.Statements.Count; i++ )
                        {
                            Visit( ifStatement.ElseBody.Statements[ i ] );
                        }
                    }
                    else
                    {
                        // Write else body
                        mSuppressIfStatementNewLine.Push( false );
                        Visit( ifStatement.ElseBody );
                    }
                }
            }

            public override void Visit( WhileStatement whileStatement )
            {
                WriteWithSeperator( "while" );
                WriteOpenParenthesis();
                Visit( whileStatement.Condition );
                WriteCloseParenthesis();
                Visit( whileStatement.Body );
            }

            public override void Visit( LabelDeclaration labelDeclaration )
            {
                Visit( labelDeclaration.Identifier );
                Write( ":" );
                WriteNewLine();
            }

            // Call
            public override void Visit( CallOperator callOperator )
            {
                Write( callOperator.Identifier.Text );

                if ( callOperator.Arguments.Count == 0 )
                {
                    Write( "()" );
                }
                else
                {
                    WriteOpenParenthesis();
                    for ( int i = 0; i < callOperator.Arguments.Count; i++ )
                    {
                        Visit( callOperator.Arguments[i] );
                        if ( i != callOperator.Arguments.Count - 1 )
                            Write( ", " );
                    }

                    WriteCloseParenthesis();
                }
            }

            // Binary operators
            public override void Visit( AdditionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " + " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( AssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " = " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( DivisionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " / " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( EqualityOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " == " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( GreaterThanOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " > " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( GreaterThanOrEqualOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " >= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( LessThanOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " < " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( LessThanOrEqualOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " <= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( LogicalAndOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " && " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( LogicalOrOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " || " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( MultiplicationOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " * " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( NonEqualityOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " != " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( SubtractionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " - " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( AdditionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " += " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( DivisionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " /= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( MultiplicationAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " *= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( SubtractionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " -= " );
                Visit( binaryOperator.Right );
            }

            // Identifiers
            public override void Visit( Identifier identifier )
            {
                Write( identifier.Text );
            }

            public override void Visit( TypeIdentifier typeIdentifier )
            {
                Write( typeIdentifier.Text );
            }

            // Literals
            public override void Visit( BoolLiteral literal )
            {
                Write( literal.Value.ToString() );
            }

            public override void Visit( FloatLiteral literal )
            {
                WriteFloatLiteral( literal );
            }

            public override void Visit( IntLiteral literal )
            {
                WriteIntegerLiteral( literal );
            }

            public override void Visit( StringLiteral literal )
            {
                WriteStringLiteral( literal );
            }

            // Unary operators
            public override void Visit( LogicalNotOperator unaryOperator )
            {
                Write( "!" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( NegationOperator unaryOperator )
            {
                Write( "-" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( PostfixDecrementOperator unaryOperator )
            {
                Visit( unaryOperator.Operand );
                Write( "--" );
            }

            public override void Visit( PostfixIncrementOperator unaryOperator )
            {
                Visit( unaryOperator.Operand );
                Write( "++" );
            }

            public override void Visit( PrefixDecrementOperator unaryOperator )
            {
                Write( "--" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( PrefixIncrementOperator unaryOperator )
            {
                Write( "++" );
                Visit( unaryOperator.Operand );
            }

            // Indent control methods
            private void IncreaseIndentation()
            {
                ++mTabLevel;
            }

            private void DecreaseIndentation()
            {
                --mTabLevel;
            }

            // Writing methods
            private void Write( string value )
            {
                mWriter.Write( value );
                mInsideLine = true;
            }

            private void WriteLine( string value )
            {
                mWriter.WriteLine( value );
                mInsideLine = false;
            }

            private void WriteWithSeperator( string value )
            {
                Write( value );
                Write( " " );
            }

            private void WriteIndentation()
            {
                var builder = new StringBuilder( mTabLevel );
                for ( int i = 0; i < mTabLevel; i++ )
                    builder.Append( "    " );
                mWriter.Write( builder.ToString() );
                mInsideLine = true;
            }

            private void WriteNewLine()
            {
                mWriter.WriteLine();
                mInsideLine = false;
            }

            private void WriteNewLineAndIndent()
            {
                WriteNewLine();
                WriteIndentation();
            }

            private void WriteIndented( string value )
            {
                WriteIndentation();
                Write( value );
            }

            private void WriteIndentedLine( string value )
            {
                WriteIndented( value );
                WriteNewLine();
            }

            // Syntax nodes
            private void WriteImport( Import import )
            {
                Write( "import" );
                WriteOpenParenthesis();
                WriteQuotedString( import.CompilationUnitFileName );
                WriteCloseParenthesis();
                WriteStatementEnd();
            }

            private void WriteComment( string value )
            {
                if ( value.Contains( "\n" ) )
                {
                    WriteIndented( "/* " );
                    Write( value );
                    WriteIndented( " /*" );
                }
                else
                {
                    WriteIndented( "// " );
                    Write( value );
                    WriteNewLine();
                }
            }

            private void WriteOpenParenthesis()
            {
                Write( "( " );
            }

            private void WriteCloseParenthesis()
            {
                Write( " )" );
            }

            // Statements
            private void WriteStatementEnd()
            {
                WriteLine( ";" );
            }

            private void WriteParameters( List<Parameter> parameters )
            {
                if ( parameters.Count == 0 )
                {
                    Write( "()" );
                }
                else
                {
                    WriteOpenParenthesis();
                    for ( int i = 0; i < parameters.Count; i++ )
                    {
                        var parameter = parameters[i];
                        Write( parameter.Type.Text );
                        Write( " " );
                        Write( parameter.Identifier.Text );
                        if ( i != parameters.Count - 1 )
                            Write( ", " );
                    }
                    WriteCloseParenthesis();
                }
            }

            // Literals
            // Integer literal
            private void WriteIntegerLiteral( IntLiteral intLiteral )
            {
                if ( IsPowerOfTwo( intLiteral.Value ) && intLiteral.Value >= 16 )
                {
                    WriteHexIntegerLiteral( intLiteral.Value );
                }
                else
                {
                    Write( intLiteral.Value.ToString() );
                }
            }

            private void WriteHexIntegerLiteral( int value )
            {
                if ( FitsInByte( value ) )
                    Write( $"0x{value:X2}" );
                else if ( FitsInShort( value ) )
                    Write( $"0x{value:X4}" );
                else
                    Write( $"0x{value:X8}" );
            }

            private bool IsPowerOfTwo( int x )
            {
                return ( x != 0 ) && ( ( x & ( x - 1 ) ) == 0 );
            }

            private bool FitsInShort( int value )
            {
                return ( ( ( value & 0xffff8000 ) + 0x8000 ) & 0xffff7fff ) == 0;
            }

            private bool FitsInByte( int value )
            {
                // doesn't catch negative values but that doesn't matter in this context
                return ( value & ~0xFF ) == 0;
            }

            // Float literal
            private void WriteFloatLiteral( FloatLiteral floatLiteral )
            {
                Write( $"{floatLiteral}f" );
            }

            // String literal
            private void WriteStringLiteral( StringLiteral stringLiteral )
            {
                WriteQuotedString( stringLiteral.Value );
            }

            private void WriteQuotedString( string value )
            {
                Write( $"\"{value}\"" );
            }

            public void Dispose()
            {
                if (mOwnsWriter)
                    mWriter.Dispose();
            }
        }
    }
}
