using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MoreLinq;

namespace AtlusScriptLib
{
    /// <summary>
    /// This class represents a mutable message script that is designed to abstract the format implementation details.
    /// </summary>
    public class MessageScript
    {
        /// <summary>
        /// Creates a <see cref="MessageScript"/> from a <see cref="MessageScriptBinary"/>.
        /// </summary>
        public static MessageScript FromBinary(MessageScriptBinary binary)
        {
            // Create new script instance & set user id, format version
            var instance = new MessageScript()
            {
                UserId = binary.Header.UserId,
                FormatVersion = binary.FormatVersion
            };

            // Convert the binary messages to their counterpart
            foreach (var messageHeader in binary.MessageHeaders)
            {
                IMessageScriptMessage message;
                int[] lineStartAddresses;
                byte[] buffer;

                switch (messageHeader.MessageType)
                {
                    case MessageScriptBinaryMessageType.Dialogue:
                        {
                            var binaryMessage = (MessageScriptBinaryDialogueMessage)messageHeader.Message.Value;
                            lineStartAddresses = binaryMessage.LineStartAddresses;
                            buffer = binaryMessage.TextBuffer;

                            if ((ushort)binaryMessage.SpeakerId == 0xFFFF)
                            {
                                message = new MessageScriptDialogueMessage(binaryMessage.Identifier);
                            }
                            else if (((ushort)binaryMessage.SpeakerId & 0x8000) == 0x8000)
                            {
                                Trace.WriteLine(binaryMessage.SpeakerId.ToString("X4"));
                                message = new MessageScriptDialogueMessage(binaryMessage.Identifier, new MessageScriptDialogueMessageVariablyNamedSpeaker());
                            }
                            else
                            {
                                var speakerName = ParseSpeakerLine(binary.SpeakerTableHeader.SpeakerNameArray
                                    .Value[binaryMessage.SpeakerId].Value);
                                message = new MessageScriptDialogueMessage(binaryMessage.Identifier, new MessageScriptDialogueMessageNamedSpeaker(speakerName));
                            }
                        }
                        break;

                    case MessageScriptBinaryMessageType.Selection:
                        {
                            var binaryMessage = (MessageScriptBinarySelectionMessage)messageHeader.Message.Value;
                            lineStartAddresses = binaryMessage.OptionStartAddresses;
                            buffer = binaryMessage.TextBuffer;

                            message = new MessageScriptSelectionMessage(binaryMessage.Identifier);
                        }
                        break;

                    default:
                        throw new ArgumentException("Unknown message type", nameof(binary));
                }

                // Parse the line data
                ParseLines(message, lineStartAddresses, buffer);

                // Add it to the message list
                instance.Messages.Add(message);
            }

            return instance;
        }

        /// <summary>
        /// Deserializes and creates a <see cref="MessageScript"/> from a file.
        /// </summary>
        public static MessageScript FromFile(string path)
        {
            var binary = MessageScriptBinary.FromFile(path);

            return FromBinary(binary);
        }

        /// <summary>
        /// Deserializes and creates a <see cref="MessageScript"/> from a stream.
        /// </summary>
        public static MessageScript FromStream(Stream stream)
        {
            var binary = MessageScriptBinary.FromStream(stream);

            return FromBinary(binary);
        }

        private static void ParseLines(IMessageScriptMessage message, int[] lineStartAddresses, byte[] buffer)
        {
            if (lineStartAddresses.Length == 0 || buffer.Length == 0)
                return;

            // The addresses are not relative to the start of the buffer
            // so we rebase the addresses first
            int firstLineAddress = lineStartAddresses[0];
            for (int i = 0; i < lineStartAddresses.Length; i++)
                lineStartAddresses[i] -= firstLineAddress;
        
            for (int lineIndex = 0; lineIndex < lineStartAddresses.Length; lineIndex++)
            {
                // Initialize a new line
                var line = new MessageScriptLine();

                // Now that the line start addresses have been rebased, we can use them as indices into the buffer
                int bufferIndex = lineStartAddresses[lineIndex];

                // Calculate the line end index
                int lineEndIndex = (lineIndex + 1) != lineStartAddresses.Length ? lineStartAddresses[lineIndex + 1] : buffer.Length;

                // Loop over the buffer until we find a 0 byte or have reached the end index
                while ( bufferIndex < lineEndIndex)
                {
                    if (!ParseToken(buffer, ref bufferIndex, out IMessageScriptLineToken token))
                        break;

                    line.Tokens.Add(token);
                }

                // Add line to list of lines
                message.Lines.Add(line);
            }
        }

        private static MessageScriptLine ParseSpeakerLine(IList<byte> bytes)
        {
            var line = new MessageScriptLine();

            for (int i = 0; i < bytes.Count; i++)
            {
                if (!ParseToken(bytes, ref i, out IMessageScriptLineToken token))
                    break;

                line.Tokens.Add(token);
            }

            return line;
        }

        private static bool ParseToken(IList<byte> buffer, ref int bufferIndex, out IMessageScriptLineToken token)
        {
            byte b = buffer[bufferIndex++];

            // Check if the current byte signifies a function
            if (b == 0)
            {
                token = null;
                return false;
            }
            else if ((b & 0xF0) == 0xF0)
            {
                token = ParseFunctionToken(b, buffer, ref bufferIndex);
            }
            else if ((b & 0x80) >= 0x80)
            {
                token = ParseCharacterCodeToken(b, buffer, ref bufferIndex);
            }
            else
            {
                token = ParseTextToken(b, buffer, ref bufferIndex);
            }

            return true;
        }

        private static MessageScriptCharacterCodeToken ParseCharacterCodeToken(byte b, IList<byte> buffer, ref int bufferIndex)
        {
            ushort value = (ushort)(b << 8 | buffer[bufferIndex++] );
            return new MessageScriptCharacterCodeToken(value);
        }

        private static MessageScriptFunctionToken ParseFunctionToken(byte b, IList<byte> buffer, ref int bufferIndex)
        {
            int functionId = (b << 8) | buffer[bufferIndex++];
            int functionTableIndex = (functionId & 0xE0) >> 5;
            int functionIndex = (functionId & 0x1F);
            int functionArgumentByteCount = (((functionId >> 8) & 0xF) - 1) * 2;
            short[] functionArguments = new short[functionArgumentByteCount / 2];

            for (int i = 0; i < functionArguments.Length; i++)
            {
                byte firstByte = (byte)(buffer[bufferIndex++] - 1);
                byte secondByte = 0;
                byte secondByteAux = buffer[bufferIndex++];

                if (secondByteAux != 0xFF)
                {
                    secondByte = (byte)(secondByteAux - 1);
                }

                functionArguments[i] = (short)((firstByte & ~0xFF00) | ((secondByte << 8) & 0xFF00));
            }

            return new MessageScriptFunctionToken(functionTableIndex, functionIndex, functionArguments);
        }

        private static MessageScriptTextToken ParseTextToken(byte b, IList<byte> buffer, ref int bufferIndex)
        {
            var accumulatedText = new List<byte>();

            while (true)
            {
                accumulatedText.Add(b);

                // Check for any condition that would end the sequence of text characters
                if ( bufferIndex == buffer.Count || buffer[bufferIndex] == 0 || (buffer[bufferIndex] & 0x80) >= 0x80 || (buffer[bufferIndex] & 0xF0) == 0xF0)
                {
                    return new MessageScriptTextToken(Encoding.ASCII.GetString(accumulatedText.ToArray()));
                }

                b = buffer[bufferIndex++];
            }
        }

        /// <summary>
        /// Gets or sets the user id. Serves as metadata.
        /// </summary>
        public short UserId { get; set; }

        /// <summary>
        /// Gets or sets the format version this script will use in its binary form.
        /// </summary>
        public MessageScriptBinaryFormatVersion FormatVersion { get; set; }

        /// <summary>
        /// Gets the list of <see cref="IMessageScriptMessage"/> in this script.
        /// </summary>
        public List<IMessageScriptMessage> Messages { get; }

        /// <summary>
        /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
        /// </summary>
        public MessageScript()
        {
            UserId = 0;
            FormatVersion = MessageScriptBinaryFormatVersion.Unknown;
            Messages = new List<IMessageScriptMessage>();
        }
    }
}
