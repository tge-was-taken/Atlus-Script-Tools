namespace AtlusScriptLib
{
    public struct MessageScriptTextToken : IMessageScriptLineToken
    {
        public string Text { get; }

        public MessageScriptTextToken(string text)
        {
            Text = text;
        }

        public override string ToString()
        {
            return Text;
        }

        // IMessageScriptToken implementation
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Text;
    }
}
