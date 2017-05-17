
using System.Collections.Generic;
using System.Globalization;
using System.IO;

using AtlusScriptLib.Common.Syntax;
using AtlusScriptLib.Common.Tokenizing;

namespace AtlusScriptLib.FunctionTables
{
    public class FunctionTableParser
    {
        private Tokenizer mTokenizer;

        public FunctionTableParser(string path)
        {
            mTokenizer = new Tokenizer(File.OpenText(path), path);
        }

        public bool TryParseEntry(out FunctionTableEntry entry)
        {
            // TODO: revise after lexer has been made
            entry = new FunctionTableEntry();

            FunctionDeclarationFlags flags;
            Identifier identifier;
            FunctionArgumentList argList = new FunctionArgumentList();
            bool unused;

            if (!mTokenizer.TryGetToken(out Token token) || !int.TryParse(token.Text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int id))
                return false;

            if (!mTokenizer.TryGetToken(out token))
                return false;      

            string type = token.Text;
            unused = type == "null";

            if (unused)
                flags = FunctionDeclarationFlags.None;
            else
            {
                flags = token.Text == "int" ? FunctionDeclarationFlags.ReturnTypeInt :
                        token.Text == "float" ? FunctionDeclarationFlags.ReturnTypeFloat :
                        token.Text == "string" ? FunctionDeclarationFlags.ReturnTypeString :
                        token.Text == "void" ? FunctionDeclarationFlags.ReturnTypeVoid :
                        FunctionDeclarationFlags.None;
            }

            string identifierStr = string.Empty;

            while (mTokenizer.TryGetToken(out token) && token.Text != "(")
            {
                identifierStr += token.Text;
            }

            identifier = new Identifier(identifierStr);

            while ( mTokenizer.TryGetToken(out token) && token.Text != ")" )
            {
                if (token.Text == ",")
                    continue;

                VariableDeclarationFlags varFlags;
                Identifier varIdentifier;

                varFlags = token.Text == "int" ? VariableDeclarationFlags.TypeInt :
                           token.Text == "float" ? VariableDeclarationFlags.TypeFloat :
                           token.Text == "string" ? VariableDeclarationFlags.TypeString :
                           VariableDeclarationFlags.None;

                if (!mTokenizer.TryGetToken(out token))
                    return false;

                varIdentifier = new Identifier(token.Text);
                argList.Arguments.Add(new VariableDeclaration(varIdentifier, varFlags));
            }

            if (!mTokenizer.TryGetToken(out token) || token.Text != ";")
                return false;

            entry = new FunctionTableEntry(id, new FunctionDeclaration(flags, identifier, argList), unused);

            return true;
        }

        public static Dictionary<int, FunctionTableEntry> Parse(string path)
        {
            var dictionary = new Dictionary<int, FunctionTableEntry>();
            var parser = new FunctionTableParser(path);

            while (parser.TryParseEntry(out FunctionTableEntry entry))
            {
                dictionary[entry.Id] = entry;
            }

            return dictionary;
        }
    }
}
