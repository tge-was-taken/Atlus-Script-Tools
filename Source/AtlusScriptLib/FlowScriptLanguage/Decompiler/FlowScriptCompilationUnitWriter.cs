using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptCompilationUnitWriter : FlowScriptSyntaxVisitor
    {
        public void Write( FlowScriptCompilationUnit compilationUnit, string path )
        {
            using ( var writingVisitor = new WriterVisitor( File.CreateText( path ) ) )
            {
                writingVisitor.Visit( compilationUnit );
            }
        }

        private class WriterVisitor : FlowScriptSyntaxVisitor, IDisposable
        {
            private readonly StreamWriter mWriter;
            private int mTabLevel;
            private bool mInsideLine;
            private FlowScriptProcedureDeclaration mProcedure;

            private readonly Stack<bool> mSuppressIfStatementNewLine;
            private readonly Stack<bool> mSuppressCompoundStatementNewline;

            public WriterVisitor( StreamWriter writer )
            {
                mWriter = writer;
                mSuppressIfStatementNewLine = new Stack< bool >();
                mSuppressCompoundStatementNewline = new Stack< bool >();
            }

            public override void Visit( FlowScriptImport import )
            {
                WriteImport( import );
            }

            // Unimplemented
            public override void Visit( FlowScriptEnumDeclaration enumDeclaration )
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

            public override void Visit( FlowScriptEnumValueDeclaration enumValueDeclaration )
            {
                Visit( enumValueDeclaration.Identifier );
                Write( " = " );
                Visit( enumValueDeclaration.Value );
            }

            public override void Visit( FlowScriptMemberAccessExpression memberAccessExpression )
            {
                Visit( memberAccessExpression.Operand );
                Write( "." );
                Visit( memberAccessExpression.Member );
            }

            public override void Visit( FlowScriptSwitchStatement switchStatement )
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
            public override void Visit( FlowScriptCompilationUnit compilationUnit )
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
                    if ( !seenFirstFunction && statement is FlowScriptFunctionDeclaration )
                    {
                        WriteNewLine();
                        WriteComment( "" );
                        WriteComment( "Function prototypes" );
                        WriteComment( "" );
                        WriteNewLine();
                        seenFirstFunction = true;
                    }

                    if ( !seenFirstVariableDeclaration && statement is FlowScriptVariableDeclaration )
                    {
                        WriteNewLine();
                        WriteComment( "" );
                        WriteComment( "Script-level variable definitions" );
                        WriteComment( "" );
                        WriteNewLine();
                        seenFirstVariableDeclaration = true;
                    }

                    if ( !seenFirstProcedure && statement is FlowScriptProcedureDeclaration )
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
                    if ( !( statement is FlowScriptProcedureDeclaration ) )
                    {
                        WriteStatementEnd();
                    }
                }
            }

            public override void Visit( FlowScriptProcedureDeclaration procedureDeclaration )
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

            public override void Visit( FlowScriptFunctionDeclaration functionDeclaration )
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

            public override void Visit( FlowScriptVariableDeclaration variableDeclaration )
            {
                if ( variableDeclaration.Modifier.ModifierType != FlowScriptModifierType.Local )
                {
                    WriteWithSeperator( FlowScriptKeywordConverter.ModifierTypeToKeyword[variableDeclaration.Modifier.ModifierType] );
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

            public override void Visit( FlowScriptStatement statement )
            {
                if ( !( statement is FlowScriptReturnStatement ) )
                    WriteIndentation();

                base.Visit( statement );

                if ( !( statement is FlowScriptCompoundStatement ) &&
                     !( statement is FlowScriptForStatement ) &&
                     !( statement is FlowScriptIfStatement ) &&
                     !( statement is FlowScriptSwitchStatement ) &&
                     !( statement is FlowScriptWhileStatement ) &&
                     !( statement is FlowScriptReturnStatement ) &&
                     !( statement is FlowScriptLabelDeclaration ) &&
                     !( statement is FlowScriptProcedureDeclaration ) )
                {
                    WriteStatementEnd();
                }
            }

            public override void Visit( FlowScriptCompoundStatement compoundStatement )
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

            public override void Visit( FlowScriptBreakStatement statement )
            {
                Write( "break" );
            }

            public override void Visit( FlowScriptContinueStatement statement )
            {
                Write( "continue" );
            }

            public override void Visit( FlowScriptReturnStatement statement )
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

            public override void Visit( FlowScriptForStatement forStatement )
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

            public override void Visit( FlowScriptGotoStatement gotoStatement )
            {
                WriteWithSeperator( "goto" );
                Write( gotoStatement.LabelIdentifier.Text );
            }

            public override void Visit( FlowScriptIfStatement ifStatement )
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
                         ifStatement.ElseBody.Statements[ 0 ] is FlowScriptIfStatement )
                    {
                        // Write else if { }, instead of else { if { } }
                        mSuppressIfStatementNewLine.Push( true );
                        Visit( (FlowScriptIfStatement) ifStatement.ElseBody.Statements[ 0 ] );
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

            public override void Visit( FlowScriptWhileStatement whileStatement )
            {
                WriteWithSeperator( "while" );
                WriteOpenParenthesis();
                Visit( whileStatement.Condition );
                WriteCloseParenthesis();
                Visit( whileStatement.Body );
            }

            public override void Visit( FlowScriptLabelDeclaration labelDeclaration )
            {
                Visit( labelDeclaration.Identifier );
                Write( ":" );
                WriteNewLine();
            }

            // Call
            public override void Visit( FlowScriptCallOperator callOperator )
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
            public override void Visit( FlowScriptAdditionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " + " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " = " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptDivisionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " / " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptEqualityOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " == " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptGreaterThanOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " > " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptGreaterThanOrEqualOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " >= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptLessThanOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " < " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptLessThanOrEqualOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " <= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptLogicalAndOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " && " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptLogicalOrOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " || " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptMultiplicationOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " * " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptNonEqualityOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " != " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptSubtractionOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " - " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptAdditionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " += " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptDivisionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " /= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptMultiplicationAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " *= " );
                Visit( binaryOperator.Right );
            }

            public override void Visit( FlowScriptSubtractionAssignmentOperator binaryOperator )
            {
                Visit( binaryOperator.Left );
                Write( " -= " );
                Visit( binaryOperator.Right );
            }

            // Identifiers
            public override void Visit( FlowScriptIdentifier identifier )
            {
                Write( identifier.Text );
            }

            public override void Visit( FlowScriptTypeIdentifier typeIdentifier )
            {
                Write( FlowScriptKeywordConverter.ValueTypeToKeyword[typeIdentifier.ValueType] );
            }

            // Literals
            public override void Visit( FlowScriptBoolLiteral literal )
            {
                Write( literal.Value.ToString() );
            }

            public override void Visit( FlowScriptFloatLiteral literal )
            {
                WriteFloatLiteral( literal );
            }

            public override void Visit( FlowScriptIntLiteral literal )
            {
                WriteIntegerLiteral( literal );
            }

            public override void Visit( FlowScriptStringLiteral literal )
            {
                WriteStringLiteral( literal );
            }

            // Unary operators
            public override void Visit( FlowScriptLogicalNotOperator unaryOperator )
            {
                Write( "!" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( FlowScriptNegationOperator unaryOperator )
            {
                Write( "-" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( FlowScriptPostfixDecrementOperator unaryOperator )
            {
                Visit( unaryOperator.Operand );
                Write( "--" );
            }

            public override void Visit( FlowScriptPostfixIncrementOperator unaryOperator )
            {
                Visit( unaryOperator.Operand );
                Write( "++" );
            }

            public override void Visit( FlowScriptPrefixDecrementOperator unaryOperator )
            {
                Write( "--" );
                Visit( unaryOperator.Operand );
            }

            public override void Visit( FlowScriptPrefixIncrementOperator unaryOperator )
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
            private void WriteImport( FlowScriptImport import )
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

            private void WriteParameters( List<FlowScriptParameter> parameters )
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
                        Write( FlowScriptKeywordConverter.ValueTypeToKeyword[parameter.Type.ValueType] );
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
            private void WriteIntegerLiteral( FlowScriptIntLiteral intLiteral )
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
            private void WriteFloatLiteral( FlowScriptFloatLiteral floatLiteral )
            {
                Write( $"{floatLiteral}f" );
            }

            // String literal
            private void WriteStringLiteral( FlowScriptStringLiteral stringLiteral )
            {
                WriteQuotedString( stringLiteral.Value );
            }

            private void WriteQuotedString( string value )
            {
                Write( $"\"{value}\"" );
            }

            public void Dispose()
            {
                ( ( IDisposable )mWriter ).Dispose();
            }
        }
    }
}
