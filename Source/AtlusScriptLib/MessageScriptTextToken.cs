namespace AtlusScriptLib
{
    public struct MessageScriptTextToken : IMessageScriptLineToken
    {
        public string Text { get; }

        public MessageScriptTextToken(string text)
        {
            Text = text;
        }

        // IMessageScriptToken implementation
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Text;
    }
}
