
using System.Collections.Generic;
using System.Globalization;
using System.IO;

using AtlusScriptLib.Shared.Syntax;
using AtlusScriptLib.Shared.Tokenizing;

namespace AtlusScriptLib.FlowScript.CommTables
{
    public class CommTableParser
    {
        private Tokenizer mTokenizer;

        public CommTableParser(string path)
        {
            mTokenizer = new Tokenizer(File.OpenText(path), path);
        }

        public bool TryParseEntry(out CommTableEntry entry)
        {
            // TODO: revise after lexer has been made
            entry = new CommTableEntry();

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
            {
                flags = FunctionDeclarationFlags.None;
            }
            else
            {
                if (type == "void")
                    flags = FunctionDeclarationFlags.ReturnTypeVoid;
                else if (type == "int")
                    flags = FunctionDeclarationFlags.ReturnTypeInt;
                else if (type == "float")
                    flags = FunctionDeclarationFlags.ReturnTypeFloat;
                else
                    flags = FunctionDeclarationFlags.None;
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

            entry = new CommTableEntry(id, new FunctionDeclaration(flags, identifier, argList), unused);

            return true;
        }

        public static Dictionary<int, CommTableEntry> Parse(string path)
        {
            var dictionary = new Dictionary<int, CommTableEntry>();
            var parser = new CommTableParser(path);

            while (parser.TryParseEntry(out CommTableEntry entry))
            {
                dictionary[entry.Id] = entry;
            }

            return dictionary;
        }
    }
}
