using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter;

public class Module
{
    public Dictionary<int, Action<FlowScriptInterpreter>> Functions;
}
