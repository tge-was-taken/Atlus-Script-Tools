using AtlusScriptLib.Shared.Syntax;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AtlusScriptLib.FlowScript.CommTables
{
    public struct CommTableEntry
    {
        public int Id { get; }

        public FunctionDeclaration Declaration { get; }

        public bool Unused { get; }

        public CommTableEntry(int id, FunctionDeclaration declaration, bool unused)
        {
            Id = id;
            Declaration = declaration;
            Unused = unused;
        }
    }

    internal class CommTableParser
    {
        private StreamReader mReader;
        private StringBuilder mBuilder;

        public static Dictionary<int, CommTableEntry> ParseTable(string path)
        {
            var parser = new CommTableParser();
            return null;
        }

        private string ReadToken()
        {
            char c;
            bool inParens = false;

            while (true)
            {
                c = (char)mReader.Read();

                if (c == '(')
                    inParens = true;
                else if (c == ')')
                    inParens = false;
                else if (c == ' ' && !inParens)
                    break;

                mBuilder.Append(c);
            }

            var ret = mBuilder.ToString();
            mBuilder.Clear();

            return ret;
        }
    }

    public static class P5CommTable
    {
        public static Dictionary<int, CommTableEntry> Entries { get; }

        static P5CommTable()
        {
            using (var reader = new StreamReader("FlowScript\\CommTables\\p5table.txt"))
            {
                var stringBuilder = new StringBuilder();

                while (!reader.EndOfStream)
                {
                    string readSpaceDelimitedToken()
                    {
                        char c;
                        while ((c = (char)reader.Read()) != ' ')
                        {
                            stringBuilder.Append(c);                            
                        }

                        var ret = stringBuilder.ToString();
                        stringBuilder.Clear();

                        return ret;
                    }

                    var tokens = reader.ReadLine().Split(' ');

                    int id = int.Parse(tokens[0].Substring(2), System.Globalization.NumberStyles.HexNumber);

                    FunctionDeclarationFlags flags = FunctionDeclarationFlags.ReturnTypeVoid;
                    if (tokens[1] == "int")
                        flags |= FunctionDeclarationFlags.ReturnTypeInt;
                    else if (tokens[2] == "float")
                        flags |= FunctionDeclarationFlags.ReturnTypeFloat;

                    var identifierWithParenthesis = tokens[3];
                    int parensStart = identifierWithParenthesis.IndexOf('(');
                    int parensEnd = identifierWithParenthesis.IndexOf(')');

                    Identifier identifier = new Identifier(identifierWithParenthesis.Substring(0, parensStart));
                    FunctionArgumentList argumentList = new FunctionArgumentList();
                    bool isUnused = false;

                    if (parensEnd != -1)
                    {
                        for (int i = 4; i < tokens.Length; i++)
                        {
                            string argumentIdentifierOrType = tokens[i];

                            Identifier argumentIdentifier = null;
                            VariableDeclarationFlags argumentFlags = VariableDeclarationFlags.None;

                            if (argumentIdentifierOrType == "int")
                                argumentFlags = VariableDeclarationFlags.TypeInt;
                            else if (argumentIdentifierOrType == "float")
                                argumentFlags = VariableDeclarationFlags.TypeFloat;
                            else if (argumentIdentifierOrType == "string")
                                argumentFlags = VariableDeclarationFlags.TypeString;
                            else if (argumentIdentifierOrType == "null")
                            {
                                isUnused = true;
                            }
                            else
                                argumentIdentifier = new Identifier(argumentIdentifierOrType.TrimEnd(new char[] { ',', ')' }));

                            if (isUnused)
                                break;

                            if (argumentIdentifier == null)
                                argumentIdentifier = new Identifier(tokens[++i].TrimEnd(new char[] { ',', ')' }));

                            argumentList.Arguments.Add(new VariableDeclaration(argumentIdentifier, argumentFlags));
                        }
                    }

                    var declaration = new FunctionDeclaration(flags, identifier, argumentList);

                    Entries.Add(id, new CommTableEntry(id, declaration, isUnused));
                }
            }
        }
    }
}
