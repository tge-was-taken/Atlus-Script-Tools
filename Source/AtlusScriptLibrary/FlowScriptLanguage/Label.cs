using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage;

/// <summary>
/// Represents a single named label in a flow script.
/// </summary>
public class Label
{
    /// <summary>
    /// Gets the name of the label.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the instruction index at which this label is located.
    /// </summary>
    public int InstructionIndex { get; }

    /// <summary>
    /// Constructs a new label.
    /// </summary>
    /// <param name="name">The name of the label.</param>
    /// <param name="instructionIndex">The instruction index at which this label is located.</param>
    public Label(string name, int instructionIndex)
    {
        Name = name;
        InstructionIndex = instructionIndex;
    }

    public override string ToString()
    {
        return $"{Name} at {InstructionIndex}";
    }

    public Label Clone()
    {
        return new Label(Name, InstructionIndex);
    }

    public bool Equals(Label other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null) return false;

        return Name == other.Name && InstructionIndex == other.InstructionIndex;
    }

    public override bool Equals(object obj) => obj is Label && Equals(obj as Label);

    public static bool Equals (Label x, Label y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null) return y is null;
        return x.Equals(y);
    }

    public override int GetHashCode() => HashCode.Combine(Name, InstructionIndex);

    public static bool operator ==(Label x, Label y) => Equals(x, y);
    public static bool operator !=(Label x, Label y) => !Equals(x, y);
}
