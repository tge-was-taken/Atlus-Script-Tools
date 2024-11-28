using System;

namespace AtlusScriptLibrary.FlowScriptLanguage;

/// <summary>
/// Represents an instruction operand value.
/// </summary>
public class Operand : IEquatable<Operand>
{
    private ushort mUshortValue;
    private uint mUIntValue;
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
    public Operand(ushort value)
    {
        Kind = ValueKind.UInt16;
        mUshortValue = value;
    }

    /// <summary>
    /// Constructs a new operand value.
    /// </summary>
    /// <param name="value">The operand value.</param>
    public Operand(uint value)
    {
        Kind = ValueKind.UInt32;
        mUIntValue = value;
    }

    /// <summary>
    /// Constructs a new operand value.
    /// </summary>
    /// <param name="value">The operand value.</param>
    public Operand(float value)
    {
        Kind = ValueKind.Single;
        mFloatValue = value;
    }

    /// <summary>
    /// Constructs a new operand value.
    /// </summary>
    /// <param name="value">The operand value.</param>
    public Operand(string value)
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
            switch (Kind)
            {
                case ValueKind.None:
                    throw new InvalidOperationException("This operand has no value");

                case ValueKind.UInt16:
                    return mUshortValue;

                case ValueKind.UInt32:
                    return mUIntValue;

                case ValueKind.Single:
                    return mFloatValue;

                case ValueKind.String:
                    return mStringValue;

                default:
                    throw new Exception("Invalid value type");
            }
        }

        set
        {
            switch (Kind)
            {
                case ValueKind.None:
                    throw new InvalidOperationException("This operand has no value");

                case ValueKind.UInt16:
                    mUshortValue = (ushort)value;
                    break;

                case ValueKind.UInt32:
                    mUIntValue = (uint)value;
                    break;

                case ValueKind.Single:
                    mFloatValue = (float)value;
                    break;

                case ValueKind.String:
                    mStringValue = (string)value;
                    break;

                default:
                    throw new Exception("Invalid value type");
            }
        }
    }

    /// <summary>
    /// Gets the <see cref="UInt16"/> operand value.
    /// </summary>
    /// <returns>The <see cref="UInt16"/> operand value.</returns>
    public ushort UInt16Value
    {
        get
        {
            if (Kind != ValueKind.UInt16)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.UInt16}");

            return mUshortValue;
        }

        set
        {
            if (Kind != ValueKind.UInt16)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.UInt16}");

            mUshortValue = value;
        }
    }

    /// <summary>
    /// Gets the <see cref="Int32"/> operand value.
    /// </summary>
    /// <returns>The <see cref="Int32"/> operand value.</returns>
    public uint UInt32Value
    {
        get
        {
            if (Kind != ValueKind.UInt32)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.UInt32}");

            return mUIntValue;
        }

        set
        {
            if (Kind != ValueKind.UInt32)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.UInt32}");

            mUIntValue = value;
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
            if (Kind != ValueKind.Single)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.Single}");

            return mFloatValue;
        }

        set
        {
            if (Kind != ValueKind.Single)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.Single}");

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
            if (Kind != ValueKind.String)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.String}");

            return mStringValue;
        }
        set
        {
            if (Kind != ValueKind.String)
                throw new InvalidOperationException($"This operand does not have a value of type {ValueKind.String}");

            mStringValue = value;
        }
    }

    /// <summary>
    /// Represents the value types an operand can contain.
    /// </summary>
    public enum ValueKind
    {
        None,
        UInt16,
        UInt32,
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

            case ValueKind.UInt16:
                return mUshortValue == other.mUshortValue;

            case ValueKind.UInt32:
                return mUIntValue == other.mUIntValue;

            case ValueKind.Single:
                return mFloatValue == other.mFloatValue;

            case ValueKind.String:
                return mStringValue == other.mStringValue;

            default:
                throw new Exception("Invalid value type");
        }
    }

    public Operand Clone()
    {
        switch (Kind)
        {
            case ValueKind.UInt16:
                return new Operand(mUshortValue);
            case ValueKind.UInt32:
                return new Operand(mUIntValue);
            case ValueKind.Single:
                return new Operand(mFloatValue);
            case ValueKind.String:
                return new Operand(mStringValue);
            default:
                throw new InvalidOperationException();
        }
    }
}