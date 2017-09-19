using System;
using System.Collections;
using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;
using AtlusScriptLib.MessageScriptLanguage;

namespace AtlusScriptLib.FlowScriptLanguage
{
    /// <summary>
    /// Provides utilities to easily build a flow script, supporting higher level constructs than are normally available.
    /// </summary>
    public class FlowScriptBuilder
    {
        private FlowScriptBinaryFormatVersion mVersion;
        private short mUserId;
        private List<FlowScriptProcedure> mProcedures;
        private MessageScript mMessageScript;

        public FlowScriptBuilder( FlowScriptBinaryFormatVersion version )
        {
            mVersion = version;
            mUserId = 0;
            mProcedures = new List<FlowScriptProcedure>();
        }

        public FlowScriptBuilder SetUserId( short userId )
        {
            mUserId = userId;
            return this;
        }

        public FlowScriptProcedureBuilder StartProcedure( string name )
        {
            return new FlowScriptProcedureBuilder( this, name );
        }

        public FlowScriptBuilder AddProcedure( FlowScriptProcedure procedure )
        {
            if ( procedure.Instructions.Count == 0 || procedure.Instructions[0].Opcode != FlowScriptOpcode.PROC )
            {
                procedure.Instructions.Insert( 0, FlowScriptInstruction.PROC( ( short )mProcedures.Count ) );
            }

            if ( procedure.Instructions[ procedure.Instructions.Count - 1 ].Opcode != FlowScriptOpcode.END )
            {
                procedure.Instructions.Add( FlowScriptInstruction.END() );
            }

            mProcedures.Add( procedure );

            return this;
        }

        public FlowScriptBuilder SetMessageScript( MessageScript messageScript )
        {
            mMessageScript = messageScript;
            return this;
        }

        public FlowScript Build()
        {
            var flowScript = new FlowScript( mVersion );
            flowScript.UserId = mUserId;
            flowScript.Procedures.AddRange( mProcedures );
            flowScript.MessageScript = mMessageScript;

            return flowScript;
        }
    }

    interface IFlowScriptBuilder
    {
        IFlowScriptProcedureBuilder StartProcedure( string name );

        IFlowScriptBuilder EndProcedure();

        FlowScript Build();
    }

    interface IFlowScriptProcedureBuilder : IFlowScriptCompoundStatementBuilder
    {
        FlowScriptProcedure Build();
    }

    interface IFlowScriptStatementBuilder
    {
        IFlowScriptStatementBuilder Instruction( FlowScriptInstruction instruction );

        IFlowScriptStatementBuilder DeclareVariable( FlowScriptVariableType type, string variableName );

        IFlowScriptStatementBuilder AssignVariable( string variableName, FlowScriptExpression value );

        // control flow
        IFlowScriptCompoundStatementBuilder If( FlowScriptExpression condition );

        IFlowScriptCompoundStatementBuilder ElseIf( FlowScriptExpression condition );

        IFlowScriptCompoundStatementBuilder Else( FlowScriptExpression condition );

        IFlowScriptCompoundStatementBuilder For( FlowScriptExpression preIterationExpression, FlowScriptExpression condition, FlowScriptExpression postIterationExpression );

        IFlowScriptCompoundStatementBuilder While( FlowScriptExpression condition );

        IFlowScriptStatementBuilder EndBranch();

        // building

        //FlowScriptCompoundStatement Build();

        IFlowScriptCompoundStatementBuilder EndStatement();
    }

    interface IFlowScriptCompoundStatementBuilder : IFlowScriptStatementBuilder
    {
        IFlowScriptCompoundStatementBuilder StartCompoundStatement();

        IFlowScriptCompoundStatementBuilder EndCompoundStatement();

        IFlowScriptStatementBuilder Statement();

        FlowScriptCompoundStatement Build();
    }

    interface IFlowScriptExpressionBuilder
    {
        // Equals
        IFlowScriptStatementBuilder Equals( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // Not Equals
        IFlowScriptStatementBuilder NotEquals( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // Less than
        IFlowScriptStatementBuilder LessThan( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // More than
        IFlowScriptStatementBuilder MoreThan( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // Less Than Or Equal
        IFlowScriptStatementBuilder LessThanOrEqual( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // More than or equal
        IFlowScriptStatementBuilder MoreThanOrEqual( FlowScriptExpression lhs, FlowScriptExpression rhs );

        // function call
        IFlowScriptStatementBuilder FunctionCall( short functionId, params object[] args );

        IFlowScriptStatementBuilder ProcedureCall( string procedureName );
    }

    public class FlowScriptProcedureBuilder
    {
        private string mName;
        private List<FlowScriptInstruction> mInstructions;
        private short mLocalVariableIndex;
        private Dictionary<string, Variable> mVariables;
        private FlowScriptBuilder mBuilder;

        public FlowScriptProcedureBuilder( FlowScriptBuilder builder, string name )
        {
            mName = name;
            mInstructions = new List<FlowScriptInstruction>();
            mVariables = new Dictionary<string, Variable>();
            mBuilder = builder;
        }

        public FlowScriptProcedureBuilder AddInstruction( FlowScriptInstruction instruction )
        {
            mInstructions.Add( instruction );
            return this;
        }

        public FlowScriptProcedureBuilder DeclareVariable( FlowScriptVariableType type, string name )
        {
            mVariables.Add( name, new Variable( name, type, false, mLocalVariableIndex++ ) );
            return this;
        }

        public FlowScriptProcedureBuilder AssignVariable( string name, object value )
        {
            var variable = mVariables[name];

            variable.Value = value;
            switch ( variable.Type )
            {
                case FlowScriptVariableType.Int32:
                    AddInstruction( FlowScriptInstruction.PUSHI( ( int )value ) );
                    AddInstruction( FlowScriptInstruction.POPLIX( variable.Index ) );
                    break;
                case FlowScriptVariableType.Float:
                    AddInstruction( FlowScriptInstruction.PUSHF( ( float )value ) );
                    AddInstruction( FlowScriptInstruction.POPLFX( variable.Index ) );
                    break;
                default:
                    throw new NotImplementedException();
            }

            return this;
        }

        public FlowScriptProcedureBuilder FunctionCall( short functionId, params object[] args )
        {
            for ( int i = 0; i < args.Length; i++ )
            {
                object arg = args[i];

                switch ( arg )
                {
                    case short shortValue:
                        AddInstruction( FlowScriptInstruction.PUSHIS( shortValue ) );
                        break;

                    case int intValue:
                        if ( (uint)intValue <= short.MaxValue )
                        {
                            AddInstruction( FlowScriptInstruction.PUSHIS( (short)intValue ) );
                        }
                        else
                        {
                            AddInstruction( FlowScriptInstruction.PUSHI( intValue ) );
                        }
                        break;
                    case float floatValue:
                        AddInstruction( FlowScriptInstruction.PUSHF( floatValue ) );
                        break;
                    case string stringValue:
                        AddInstruction( FlowScriptInstruction.PUSHSTR( stringValue ) );
                        break;
                    default:
                        throw new ArgumentException( $"Argument {i}'s type is unsupported ({arg.GetType().FullName})" );
                }
            }

            AddInstruction( FlowScriptInstruction.COMM( functionId ) );
            return this;
        }

        public FlowScriptBuilder EndProcedure()
        {
            return mBuilder.AddProcedure( new FlowScriptProcedure( mName, mInstructions ) );
        }

        public FlowScriptProcedure Build()
        {
            return new FlowScriptProcedure( mName, mInstructions );
        }

        class Variable
        {
            public string Name { get; }
            
            public FlowScriptVariableType Type { get; }

            public object Value { get; set; }

            public bool IsGlobal { get; }

            public bool IsAssigned { get; }

            public short Index { get; }

            public Variable( string name, FlowScriptVariableType type, bool isGlobal, short index )
            {
                Name = name;
                Type = type;
                IsGlobal = isGlobal;
                IsAssigned = true;
            }
        }
    }

    public enum FlowScriptStatementType
    {
        NullStatement,
        CompoundStatement,
        ExpressionStatement,
        SelectionStatement,
        IterationStatement,
        JumpStatement,
    }

    public class FlowScriptStatement
    {
        public FlowScriptStatementType StatementType { get; }

        protected FlowScriptStatement( FlowScriptStatementType type )
        {
            StatementType = type;
        }
    }

    public class FlowScriptCompoundStatement : FlowScriptStatement, IEnumerable<FlowScriptStatement>
    {
        public List<FlowScriptStatement> Statements { get; }

        public FlowScriptCompoundStatement( List<FlowScriptStatement> statements ) : base( FlowScriptStatementType.CompoundStatement )
        {
        }

        public IEnumerator<FlowScriptStatement> GetEnumerator()
        {
            return Statements.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Statements.GetEnumerator();
        }
    }

    public enum FlowScriptExpressionType
    {
        IdentfierExpression,
        SuffixExpression,
        PostfixExpression,
        UnaryOperatorExpression,
        BinaryOperatorExpression,
        ConditionalOperatorExpression,
        ConstantExpression
    }

    public class FlowScriptExpression : FlowScriptStatement
    {
        public FlowScriptExpressionType ExpressionType { get; }

        public object Value { get; }

        public FlowScriptExpression( FlowScriptExpressionType type, object value ) : base( FlowScriptStatementType.ExpressionStatement )
        {
            Value = value;
        }
    }

    public class FlowScriptExpression<T> : FlowScriptExpression
    {
        public new T Value
        {
            get => ( T )base.Value;
        }

        public FlowScriptExpression( FlowScriptExpressionType type, T value ) : base( type, value )
        {
        }
    }

    public class FlowScriptConstant<T> : FlowScriptExpression<T>
    {
        public FlowScriptConstant( T value ) : base( FlowScriptExpressionType.ConstantExpression, value )
        {
        }
    }

    public class FlowScriptIdentifier : FlowScriptExpression<FlowScriptIdentifierReference>
    {
        public FlowScriptIdentifier( FlowScriptIdentifierReference value ) : base( FlowScriptExpressionType.IdentfierExpression, value )
        {
        }
    }

    public enum FlowScriptIdentifierReferenceType
    {
        Unknown,
        Variable,
        Procedure,
        Function,
    }

    public class FlowScriptIdentifierReference
    {
        public FlowScriptIdentifierReferenceType ReferenceType { get; }

        public string Identifier { get; }

        public FlowScriptIdentifierReference( FlowScriptIdentifierReferenceType type, string identifier )
        {
            ReferenceType = type;
            Identifier = identifier;
        }
    }

    public class FlowScriptVariableIdentifierReference : FlowScriptIdentifierReference
    {
        public int Index { get; }

        public FlowScriptVariableIdentifierReference( string identifier, int index ) : base( FlowScriptIdentifierReferenceType.Variable, identifier )
        {
            Index = index;
        }
    }
}
