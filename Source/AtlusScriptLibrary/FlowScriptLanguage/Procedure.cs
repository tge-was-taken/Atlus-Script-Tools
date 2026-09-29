using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage;

public class Procedure : IEquatable<Procedure>
{
    public string Name { get; set; }

    public List<Instruction> Instructions { get; }

    public List<Label> Labels { get; }

    public Procedure(string name)
    {
        Name = name;
        Instructions = new List<Instruction>();
        Labels = new List<Label>();
    }

    public Procedure(string name, List<Instruction> instructions)
    {
        Name = name;
        Instructions = instructions;
        Labels = new List<Label>();
    }

    public Procedure(string name, List<Instruction> instructions, List<Label> labels)
    {
        Name = name;
        Instructions = instructions;
        Labels = labels;
    }

    public override string ToString()
    {
        return $"{Name} with {Instructions.Count} instructions";
    }

    public Procedure Clone()
    {
        var p = new Procedure(Name);
        foreach (var i in Instructions)
            p.Instructions.Add(i.Clone());

        foreach (var l in Labels)
            p.Labels.Add(l.Clone());

        return p;
    }

    public bool Equals(Procedure other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null) return false;

        if (Name != other.Name) return false;
        if (!Instructions.SequenceEqual(other.Instructions)) return false;
        return Labels.SequenceEqual(other.Labels);
    }

    public override bool Equals(object obj) => obj is Procedure && Equals(obj as Procedure);

    public static bool Equals(Procedure a, Procedure b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a is null) return b is null;
        return a.Equals(b);
    }

    public override int GetHashCode() => HashCode.Combine(Name, Instructions, Labels);

    public static bool operator ==(Procedure x, Procedure y) => Equals(x, y);
    public static bool operator !=(Procedure x, Procedure y) => !Equals(x, y);
}
