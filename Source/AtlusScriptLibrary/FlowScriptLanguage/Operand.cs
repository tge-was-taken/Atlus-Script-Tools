using System;

namespace AtlusScriptLibrary.FlowScriptLanguage
{
    /// <summary>
    /// Represents an instruction operand value.
    /// </summary>
    public class Operand : IEquatable<Operand>
    {
        private short mShortValue;
        private int mIntValue;
        private float mFloatValue;
        private string mStringValue;

        /// <summary>
        /// Gets the value type of the operand.
        /// </summary>
        public ValueKind Kind { get; }

        /// <summary>
        /// Constructs a new operand value.
        /// </summary>
        /// <param name="value">The operand value.</param>
        public Operand( short value )
        {
            Kind = ValueKind.Int16;
            mShortValue = value;
        }

        /// <summary>
        /// Constructs a new operand value.
        /// </summary>
        /// <param name="value">The operand value.</param>
        public Operand( int value )
        {
            Kind = ValueKind.Int32;
            mIntValue = value;
        }

        /// <summary>
        /// Constructs a new operand value.
        /// </summary>
        /// <param name="value">The operand value.</param>
        public Operand( float value )
        {
            Kind = ValueKind.Single;
            mFloatValue = value;
        }

        /// <summary>
        /// Constructs a new operand value.
        /// </summary>
        /// <param name="value">The operand value.</param>
        public Operand( string value )
        {
            Kind = ValueKind.String;
            mStringValue = value;
        }

        /// <summary>
        /// Gets the operand value.
        /// </summary>
        /// <returns>The operand value.</returns>
        public object Value
        {
            get
            {
                switch ( Kind )
                {
                    case ValueKind.None:
                        throw new InvalidOperationException( "This operand has no value" );

                    case ValueKind.Int16:
                        return mShortValue;

                    case ValueKind.Int32:
                        return mIntValue;

                    case ValueKind.Single:
                        return mFloatValue;

                    case ValueKind.String:
                        return mStringValue;

                    default:
                        throw new Exception( "Invalid value type" );
                }
            }

            set
            {
                switch ( Kind )
                {
                    case ValueKind.None:
                        throw new InvalidOperationException( "This operand has no value" );

                    case ValueKind.Int16:
                        mShortValue = ( short )value;
                        break;

                    case ValueKind.Int32:
                        mIntValue = ( int )value;
                        break;

                    case ValueKind.Single:
                        mFloatValue = ( float )value;
                        break;

                    case ValueKind.String:
                        mStringValue = ( string )value;
                        break;

                    default:
                        throw new Exception( "Invalid value type" );
                }
            }
        }

        /// <summary>
        /// Gets the <see cref="Int16"/> operand value.
        /// </summary>
        /// <returns>The <see cref="Int16"/> operand value.</returns>
        public short Int16Value
        {
            get
            {
                if ( Kind != ValueKind.Int16 )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Int16}" );

                return mShortValue;
            }

            set
            {
                if ( Kind != ValueKind.Int16 )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Int16}" );

                mShortValue = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="Int32"/> operand value.
        /// </summary>
        /// <returns>The <see cref="Int32"/> operand value.</returns>
        public int Int32Value
        {
            get
            {
                if ( Kind != ValueKind.Int32 )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Int32}" );

                return mIntValue;
            }

            set
            {
                if ( Kind != ValueKind.Int32 )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Int32}" );

                mIntValue = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="Single"/> operand value.
        /// </summary>
        /// <returns>The <see cref="Single"/> operand value.</returns>
        public float SingleValue
        {
            get
            {
                if ( Kind != ValueKind.Single )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Single}" );

                return mFloatValue;
            }

            set
            {
                if ( Kind != ValueKind.Single )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.Single}" );

                mFloatValue = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="String"/> operand value.
        /// </summary>
        /// <returns>The <see cref="String"/> operand value.</returns>
        public string StringValue
        {
            get
            {
                if ( Kind != ValueKind.String )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.String}" );

                return mStringValue;
            }
            set
            {
                if ( Kind != ValueKind.String )
                    throw new InvalidOperationException( $"This operand does not have a value of type {ValueKind.String}" );

                mStringValue = value;
            }
        }

        /// <summary>
        /// Represents the value types an operand can contain.
        /// </summary>
        public enum ValueKind
        {
            None,
            Int16,
            Int32,
            Single,
            String
        }

        public override string ToString()
        {
            return Value.ToString();
        }

        public bool Equals(Operand other)
        {
            if (Kind != other.Kind)
                return false;

            switch (Kind)
            {
                case ValueKind.None:
                    return true;

                case ValueKind.Int16:
                    return mShortValue == other.mShortValue;

                case ValueKind.Int32:
                    return mIntValue == other.mIntValue;

                case ValueKind.Single:
                    return mFloatValue == other.mFloatValue;

                case ValueKind.String:
                    return mStringValue == other.mStringValue;

                default:
                    throw new Exception("Invalid value type");
            }
        }
    }
}