using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class ScopeContext
{
    public ScopeContext Parent { get; }

    public Dictionary<string, FunctionInfo> Functions { get; }

    public Dictionary<string, ProcedureInfo> Procedures { get; }

    public Dictionary<string, VariableInfo> Variables { get; }

    public Dictionary<string, Enum> Enums { get; }

    public LabelInfo BreakLabel { get; set; }

    public LabelInfo ContinueLabel { get; set; }

    public Dictionary<Expression, LabelInfo> SwitchLabels { get; set; }

    public ScopeContext(ScopeContext parent)
    {
        Parent = parent;
        Functions = new Dictionary<string, FunctionInfo>();
        Procedures = new Dictionary<string, ProcedureInfo>();
        Variables = new Dictionary<string, VariableInfo>();
        Enums = new Dictionary<string, Enum>();
    }

    public bool TryGetBreakLabel(out LabelInfo label)
    {
        if (BreakLabel != null)
        {
            label = BreakLabel;
            return true;
        }

        if (Parent != null)
            return Parent.TryGetBreakLabel(out label);

        label = null;
        return false;
    }

    public bool TryGetContinueLabel(out LabelInfo label)
    {
        if (ContinueLabel != null)
        {
            label = ContinueLabel;
            return true;
        }

        if (Parent != null)
            return Parent.TryGetContinueLabel(out label);

        label = null;
        return false;
    }

    public bool TryGetFunction(string name, out FunctionInfo function)
    {
        if (!Functions.TryGetValue(name, out function))
        {
            if (Parent == null)
                return false;

            if (!Parent.TryGetFunction(name, out function))
                return false;
        }

        return true;
    }

    public bool TryGetProcedure(string name, out ProcedureInfo procedure)
    {
        if (!Procedures.TryGetValue(name, out procedure))
        {
            if (Parent == null)
                return false;

            if (!Parent.TryGetProcedure(name, out procedure))
                return false;
        }

        return true;
    }

    public bool TryGetVariable(string name, out VariableInfo variable)
    {
        if (!Variables.TryGetValue(name, out variable))
        {
            if (Parent == null)
                return false;

            if (!Parent.TryGetVariable(name, out variable))
                return false;
        }

        return true;
    }

    public bool TryGetEnum(string name, out Enum enumDeclaration)
    {
        if (!Enums.TryGetValue(name, out enumDeclaration))
        {
            if (Parent == null)
                return false;

            if (!Parent.TryGetEnum(name, out enumDeclaration))
                return false;
        }

        return true;
    }

    public bool TryGetLabel(Expression expression, out LabelInfo label)
    {
        if (SwitchLabels == null || (label = SwitchLabels.SingleOrDefault(x => x.Key.GetHashCode() == expression.GetHashCode()).Value) == null)
        {
            if (Parent == null)
            {
                label = null;
                return false;
            }

            if (!Parent.TryGetLabel(expression, out label))
                return false;
        }

        return true;
    }

    public bool TryDeclareFunction(FunctionDeclaration declaration)
    {
        if (TryGetFunction(declaration.Identifier.Text, out _))
            return false;

        var function = new FunctionInfo();
        function.Declaration = declaration;
        function.Index = (short)declaration.Index.Value;

        Functions[declaration.Identifier.Text] = function;

        return true;
    }

        public bool TryDeclareFunctions(FunctionDeclaration[] declarations)
        {
            foreach(var declaration in declarations)
            {
                if(!TryDeclareFunction(declaration))
                    return false;
            }
            return true;
        }


        public bool TryDeclareProcedure( ProcedureDeclaration declaration, out ProcedureInfo procedure )
        {
            if ( TryGetProcedure( declaration.Identifier.Text, out procedure ) )
            {
                return false;
            }

        var p = new ProcedureInfo();
        p.Declaration = declaration;
        p.IndexForced = declaration.Index != null;
        p.Index = !p.IndexForced ? (short)Procedures.Count : (short)declaration.Index.Value;
        if (Procedures.Any(x => x.Value.Index == p.Index))
        {
            var duplicate = !p.IndexForced ? p : Procedures.Values.FirstOrDefault(x => x.Index == p.Index && !x.IndexForced);
            if (duplicate == null)
                duplicate = p; // If there's nothing else that can be replaced then this just can't have its index forced
            short newIndex = 0;
            while (Procedures.Any(x => x.Value.Index == newIndex))
                newIndex++;
            duplicate.Index = newIndex;
        }
        Procedures[declaration.Identifier.Text] = procedure = p;
        declaration.Index = p.Index;
        return true;
    }

    public bool TryDeclareProcedure(ProcedureDeclaration declaration, Procedure compiled, out ProcedureInfo procedure)
    {
        if (!TryDeclareProcedure(declaration, out procedure))
            return false;

        procedure.Compiled = compiled;
        procedure.OriginalCompiled = compiled.Clone();
        return true;
    }

    public bool TryDeclareVariable(VariableDeclaration declaration)
    {
        return TryDeclareVariable(declaration, -1);
    }

    public bool TryDeclareVariable(VariableDeclaration declaration, short index, int size = 1)
    {
        if (TryGetVariable(declaration.Identifier.Text, out _))
            return false;

        var variable = new VariableInfo();
        variable.Declaration = declaration;
        variable.Index = index;
        variable.Size = size;

        Variables[declaration.Identifier.Text] = variable;

        return true;
    }

    public bool TryDeclareEnum(EnumDeclaration declaration)
    {
        if (TryGetEnum(declaration.Identifier.Text, out _))
            return false;

        var enumType = new Enum
        {
            Declaration = declaration,
            Members = declaration.Values.ToDictionary(x => x.Identifier.Text, y => y.Value)
        };

        int nextMemberValue = 0;
        bool anyImplicitValues = false;

        for (int i = 0; i < enumType.Members.Count; i++)
        {
            var key = enumType.Members.Keys.ElementAt(i);
            var value = enumType.Members[key];

            if (value == null)
            {
                enumType.Members[key] = new IntLiteral(nextMemberValue++);
                anyImplicitValues = true;
            }
            else
            {
                if (!TryGetNextMemberValue(enumType.Members, value, out nextMemberValue))
                {
                    // Only error if there are any implicit values
                    if (anyImplicitValues)
                        return false;
                }
            }
        }

        Enums[declaration.Identifier.Text] = enumType;

        return true;
    }

    private bool TryGetNextMemberValue(Dictionary<string, Expression> members, Expression enumValue, out int nextMemberValue)
    {
        if (enumValue is IntLiteral intLiteral)
        {
            nextMemberValue = intLiteral.Value + 1;
            return true;
        }
        if (enumValue is Identifier identifier)
        {
            if (members.TryGetValue(identifier.Text, out var value))
            {
                if (!TryGetNextMemberValue(members, value, out nextMemberValue))
                    return false;
            }
        }

        nextMemberValue = -1;
        return false;
    }

    public VariableInfo GenerateVariable(ValueKind kind, short index)
    {
        var declaration = new VariableDeclaration(
            new VariableModifier(VariableModifierKind.Local),
            new TypeIdentifier(kind),
            new Identifier(kind, $"<>__CompilerGenerated{kind}Variable{index}"),
            null);

        bool result;
        result = TryDeclareVariable(declaration, index);
        Debug.Assert(result);

        result = TryGetVariable(declaration.Identifier.Text, out var variable);
        Debug.Assert(result);

        return variable;
    }
}
