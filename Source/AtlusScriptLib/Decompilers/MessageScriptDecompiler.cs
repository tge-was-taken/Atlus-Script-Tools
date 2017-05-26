using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Decompilers
{
    public class MessageScriptDecompiler
    {
        private MessageScript mScript;

        public MessageScriptDecompiler(MessageScript script)
        {
            mScript = script;
        }

        public void Decompile(string path)
        {
            using (var writer = File.CreateText(path))
            {
                foreach (var message in mScript.Messages)
                {
                    switch (message.Type)
                    {
                        case MessageScriptMessageType.Dialogue:

                            var dialogueMessage = (MessageScriptDialogueMessage)message;
                            if (dialogueMessage.Speaker == null)
                            {
                                writer.WriteLine($"[d {message.Identifier}]");
                            }
                            else if (dialogueMessage.Speaker.Type == MessageScriptDialogueMessageSpeakerType.Named)
                            {
                                writer.WriteLine($"[d {message.Identifier} \"{dialogueMessage.Speaker}\"]");
                            }
                            else if (dialogueMessage.Speaker.Type == MessageScriptDialogueMessageSpeakerType.VariablyNamed)
                            {
                                writer.WriteLine($"[d {message.Identifier} var]");
                            }

                            break;

                        case MessageScriptMessageType.Selection:
                            writer.WriteLine($"[s {message.Identifier}]");
                            break;
                    }

                    foreach (var line in message.Lines)
                    {
                        foreach (var token in line.Tokens)
                        {
                            switch (token.Type)
                            {
                                case MessageScriptTokenType.Text:
                                    foreach (var c in ((MessageScriptTextToken)token).Text)
                                    {
                                        if (c == 0x0A)
                                            writer.Write("[n]");
                                        else
                                            writer.Write(c);
                                    }
                                    break;

                                case MessageScriptTokenType.Function:
                                    {
                                        var function = (MessageScriptFunctionToken)token;
                                        writer.Write($"[f {function.FunctionTableIndex} {function.FunctionIndex}");
                                        foreach (var arg in function.Arguments)
                                            writer.Write($" {arg}");
                                        writer.Write("]");
                                    }
                                    break;
                            }
                        }

                        writer.WriteLine("[e]");
                    }

                    writer.WriteLine();
                }
            }
        }
    }
}
