//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     ANTLR Version: 4.6.4
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

// Generated from ..\..\..\AtlusScriptLibrary\MessageScriptLanguage\Compiler\Parser\MessageScriptParser.g4 by ANTLR 4.6.4

// Unreachable code detected
#pragma warning disable 0162
// The variable '...' is assigned but its value is never used
#pragma warning disable 0219
// Missing XML comment for publicly visible type or member '...'
#pragma warning disable 1591
// Ambiguous reference in cref attribute
#pragma warning disable 419

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser {
using Antlr4.Runtime;
using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Tree;
using System.Collections.Generic;
using DFA = Antlr4.Runtime.Dfa.DFA;

[System.CodeDom.Compiler.GeneratedCode("ANTLR", "4.6.4")]
[System.CLSCompliant(false)]
public partial class MessageScriptParser : Parser {
	public const int
		OpenCode=1, CloseText=2, Text=3, MessageDialogTagId=4, SelectionDialogTagId=5, 
		SelectionDialogPatternId=6, CloseCode=7, OpenText=8, IntLiteral=9, Identifier=10, 
		Whitespace=11, BlockComment=12;
	public const int
		RULE_compilationUnit = 0, RULE_dialog = 1, RULE_messageDialog = 2, RULE_speakerName = 3, 
		RULE_selectionDialog = 4, RULE_selectionDialogPattern = 5, RULE_tokenText = 6, 
		RULE_token = 7, RULE_expression = 8;
	public static readonly string[] ruleNames = {
		"compilationUnit", "dialog", "messageDialog", "speakerName", "selectionDialog", 
		"selectionDialogPattern", "tokenText", "token", "expression"
	};

	private static readonly string[] _LiteralNames = {
		null, null, null, null, null, "'sel'"
	};
	private static readonly string[] _SymbolicNames = {
		null, "OpenCode", "CloseText", "Text", "MessageDialogTagId", "SelectionDialogTagId", 
		"SelectionDialogPatternId", "CloseCode", "OpenText", "IntLiteral", "Identifier", 
		"Whitespace", "BlockComment"
	};
	public static readonly IVocabulary DefaultVocabulary = new Vocabulary(_LiteralNames, _SymbolicNames);

	[System.Obsolete("Use Vocabulary instead.")]
	public static readonly string[] tokenNames = GenerateTokenNames(DefaultVocabulary, _SymbolicNames.Length);

	private static string[] GenerateTokenNames(IVocabulary vocabulary, int length) {
		string[] tokenNames = new string[length];
		for (int i = 0; i < tokenNames.Length; i++) {
			tokenNames[i] = vocabulary.GetLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = vocabulary.GetSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}

		return tokenNames;
	}

	[System.Obsolete("Use IRecognizer.Vocabulary instead.")]
	public override string[] TokenNames
	{
		get
		{
			return tokenNames;
		}
	}

	[NotNull]
	public override IVocabulary Vocabulary
	{
		get
		{
			return DefaultVocabulary;
		}
	}

	public override string GrammarFileName { get { return "MessageScriptParser.g4"; } }

	public override string[] RuleNames { get { return ruleNames; } }

	public override string SerializedAtn { get { return _serializedATN; } }

	public MessageScriptParser(ITokenStream input)
		: base(input)
	{
		_interp = new ParserATNSimulator(this,_ATN);
	}
	public partial class CompilationUnitContext : ParserRuleContext {
		public ITerminalNode Eof() { return GetToken(MessageScriptParser.Eof, 0); }
		public DialogContext[] dialog() {
			return GetRuleContexts<DialogContext>();
		}
		public DialogContext dialog(int i) {
			return GetRuleContext<DialogContext>(i);
		}
		public CompilationUnitContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_compilationUnit; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterCompilationUnit(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitCompilationUnit(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitCompilationUnit(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public CompilationUnitContext compilationUnit() {
		CompilationUnitContext _localctx = new CompilationUnitContext(_ctx, State);
		EnterRule(_localctx, 0, RULE_compilationUnit);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 21;
			_errHandler.Sync(this);
			_la = _input.La(1);
			while (_la==OpenCode || _la==Text) {
				{
				{
				State = 18; dialog();
				}
				}
				State = 23;
				_errHandler.Sync(this);
				_la = _input.La(1);
			}
			State = 24; Match(Eof);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class DialogContext : ParserRuleContext {
		public MessageDialogContext messageDialog() {
			return GetRuleContext<MessageDialogContext>(0);
		}
		public SelectionDialogContext selectionDialog() {
			return GetRuleContext<SelectionDialogContext>(0);
		}
		public ITerminalNode[] Text() { return GetTokens(MessageScriptParser.Text); }
		public ITerminalNode Text(int i) {
			return GetToken(MessageScriptParser.Text, i);
		}
		public DialogContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_dialog; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterDialog(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitDialog(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitDialog(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public DialogContext dialog() {
		DialogContext _localctx = new DialogContext(_ctx, State);
		EnterRule(_localctx, 2, RULE_dialog);
		int _la;
		try {
			int _alt;
			EnterOuterAlt(_localctx, 1);
			{
			State = 29;
			_errHandler.Sync(this);
			_la = _input.La(1);
			while (_la==Text) {
				{
				{
				State = 26; Match(Text);
				}
				}
				State = 31;
				_errHandler.Sync(this);
				_la = _input.La(1);
			}
			State = 34;
			_errHandler.Sync(this);
			switch ( Interpreter.AdaptivePredict(_input,2,_ctx) ) {
			case 1:
				{
				State = 32; messageDialog();
				}
				break;

			case 2:
				{
				State = 33; selectionDialog();
				}
				break;
			}
			State = 39;
			_errHandler.Sync(this);
			_alt = Interpreter.AdaptivePredict(_input,3,_ctx);
			while ( _alt!=2 && _alt!=global::Antlr4.Runtime.Atn.ATN.InvalidAltNumber ) {
				if ( _alt==1 ) {
					{
					{
					State = 36; Match(Text);
					}
					} 
				}
				State = 41;
				_errHandler.Sync(this);
				_alt = Interpreter.AdaptivePredict(_input,3,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class MessageDialogContext : ParserRuleContext {
		public ITerminalNode OpenCode() { return GetToken(MessageScriptParser.OpenCode, 0); }
		public ITerminalNode MessageDialogTagId() { return GetToken(MessageScriptParser.MessageDialogTagId, 0); }
		public ITerminalNode Identifier() { return GetToken(MessageScriptParser.Identifier, 0); }
		public ITerminalNode CloseCode() { return GetToken(MessageScriptParser.CloseCode, 0); }
		public TokenTextContext tokenText() {
			return GetRuleContext<TokenTextContext>(0);
		}
		public SpeakerNameContext speakerName() {
			return GetRuleContext<SpeakerNameContext>(0);
		}
		public MessageDialogContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_messageDialog; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterMessageDialog(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitMessageDialog(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitMessageDialog(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public MessageDialogContext messageDialog() {
		MessageDialogContext _localctx = new MessageDialogContext(_ctx, State);
		EnterRule(_localctx, 4, RULE_messageDialog);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 42; Match(OpenCode);
			State = 43; Match(MessageDialogTagId);
			State = 44; Match(Identifier);
			State = 46;
			_errHandler.Sync(this);
			_la = _input.La(1);
			if (_la==OpenText) {
				{
				State = 45; speakerName();
				}
			}

			State = 48; Match(CloseCode);
			State = 49; tokenText();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class SpeakerNameContext : ParserRuleContext {
		public ITerminalNode OpenText() { return GetToken(MessageScriptParser.OpenText, 0); }
		public TokenTextContext tokenText() {
			return GetRuleContext<TokenTextContext>(0);
		}
		public ITerminalNode CloseText() { return GetToken(MessageScriptParser.CloseText, 0); }
		public SpeakerNameContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_speakerName; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterSpeakerName(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitSpeakerName(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitSpeakerName(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public SpeakerNameContext speakerName() {
		SpeakerNameContext _localctx = new SpeakerNameContext(_ctx, State);
		EnterRule(_localctx, 6, RULE_speakerName);
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 51; Match(OpenText);
			State = 52; tokenText();
			State = 53; Match(CloseText);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class SelectionDialogContext : ParserRuleContext {
		public ITerminalNode OpenCode() { return GetToken(MessageScriptParser.OpenCode, 0); }
		public ITerminalNode SelectionDialogTagId() { return GetToken(MessageScriptParser.SelectionDialogTagId, 0); }
		public ITerminalNode Identifier() { return GetToken(MessageScriptParser.Identifier, 0); }
		public ITerminalNode CloseCode() { return GetToken(MessageScriptParser.CloseCode, 0); }
		public TokenTextContext tokenText() {
			return GetRuleContext<TokenTextContext>(0);
		}
		public SelectionDialogPatternContext selectionDialogPattern() {
			return GetRuleContext<SelectionDialogPatternContext>(0);
		}
		public SelectionDialogContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_selectionDialog; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterSelectionDialog(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitSelectionDialog(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitSelectionDialog(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public SelectionDialogContext selectionDialog() {
		SelectionDialogContext _localctx = new SelectionDialogContext(_ctx, State);
		EnterRule(_localctx, 8, RULE_selectionDialog);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 55; Match(OpenCode);
			State = 56; Match(SelectionDialogTagId);
			State = 57; Match(Identifier);
			State = 59;
			_errHandler.Sync(this);
			_la = _input.La(1);
			if (_la==SelectionDialogPatternId || _la==IntLiteral) {
				{
				State = 58; selectionDialogPattern();
				}
			}

			State = 61; Match(CloseCode);
			State = 62; tokenText();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class SelectionDialogPatternContext : ParserRuleContext {
		public ITerminalNode IntLiteral() { return GetToken(MessageScriptParser.IntLiteral, 0); }
		public ITerminalNode SelectionDialogPatternId() { return GetToken(MessageScriptParser.SelectionDialogPatternId, 0); }
		public SelectionDialogPatternContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_selectionDialogPattern; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterSelectionDialogPattern(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitSelectionDialogPattern(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitSelectionDialogPattern(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public SelectionDialogPatternContext selectionDialogPattern() {
		SelectionDialogPatternContext _localctx = new SelectionDialogPatternContext(_ctx, State);
		EnterRule(_localctx, 10, RULE_selectionDialogPattern);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 64;
			_la = _input.La(1);
			if ( !(_la==SelectionDialogPatternId || _la==IntLiteral) ) {
			_errHandler.RecoverInline(this);
			} else {
				if (_input.La(1) == TokenConstants.Eof) {
					matchedEOF = true;
				}

				_errHandler.ReportMatch(this);
				Consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class TokenTextContext : ParserRuleContext {
		public TokenContext[] token() {
			return GetRuleContexts<TokenContext>();
		}
		public TokenContext token(int i) {
			return GetRuleContext<TokenContext>(i);
		}
		public ITerminalNode[] Text() { return GetTokens(MessageScriptParser.Text); }
		public ITerminalNode Text(int i) {
			return GetToken(MessageScriptParser.Text, i);
		}
		public TokenTextContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_tokenText; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterTokenText(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitTokenText(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitTokenText(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public TokenTextContext tokenText() {
		TokenTextContext _localctx = new TokenTextContext(_ctx, State);
		EnterRule(_localctx, 12, RULE_tokenText);
		try {
			int _alt;
			EnterOuterAlt(_localctx, 1);
			{
			State = 70;
			_errHandler.Sync(this);
			_alt = Interpreter.AdaptivePredict(_input,7,_ctx);
			while ( _alt!=2 && _alt!=global::Antlr4.Runtime.Atn.ATN.InvalidAltNumber ) {
				if ( _alt==1 ) {
					{
					State = 68;
					_errHandler.Sync(this);
					switch (_input.La(1)) {
					case OpenCode:
						{
						State = 66; token();
						}
						break;
					case Text:
						{
						State = 67; Match(Text);
						}
						break;
					default:
						throw new NoViableAltException(this);
					}
					} 
				}
				State = 72;
				_errHandler.Sync(this);
				_alt = Interpreter.AdaptivePredict(_input,7,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class TokenContext : ParserRuleContext {
		public ITerminalNode OpenCode() { return GetToken(MessageScriptParser.OpenCode, 0); }
		public ITerminalNode Identifier() { return GetToken(MessageScriptParser.Identifier, 0); }
		public ITerminalNode CloseCode() { return GetToken(MessageScriptParser.CloseCode, 0); }
		public ExpressionContext[] expression() {
			return GetRuleContexts<ExpressionContext>();
		}
		public ExpressionContext expression(int i) {
			return GetRuleContext<ExpressionContext>(i);
		}
		public TokenContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_token; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterToken(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitToken(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitToken(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public TokenContext token() {
		TokenContext _localctx = new TokenContext(_ctx, State);
		EnterRule(_localctx, 14, RULE_token);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 73; Match(OpenCode);
			State = 74; Match(Identifier);
			State = 78;
			_errHandler.Sync(this);
			_la = _input.La(1);
			while (_la==IntLiteral || _la==Identifier) {
				{
				{
				State = 75; expression();
				}
				}
				State = 80;
				_errHandler.Sync(this);
				_la = _input.La(1);
			}
			State = 81; Match(CloseCode);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public partial class ExpressionContext : ParserRuleContext {
		public ITerminalNode IntLiteral() { return GetToken(MessageScriptParser.IntLiteral, 0); }
		public ITerminalNode Identifier() { return GetToken(MessageScriptParser.Identifier, 0); }
		public ExpressionContext(ParserRuleContext parent, int invokingState)
			: base(parent, invokingState)
		{
		}
		public override int RuleIndex { get { return RULE_expression; } }
		public override void EnterRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.EnterExpression(this);
		}
		public override void ExitRule(IParseTreeListener listener) {
			IMessageScriptParserListener typedListener = listener as IMessageScriptParserListener;
			if (typedListener != null) typedListener.ExitExpression(this);
		}
		public override TResult Accept<TResult>(IParseTreeVisitor<TResult> visitor) {
			IMessageScriptParserVisitor<TResult> typedVisitor = visitor as IMessageScriptParserVisitor<TResult>;
			if (typedVisitor != null) return typedVisitor.VisitExpression(this);
			else return visitor.VisitChildren(this);
		}
	}

	[RuleVersion(0)]
	public ExpressionContext expression() {
		ExpressionContext _localctx = new ExpressionContext(_ctx, State);
		EnterRule(_localctx, 16, RULE_expression);
		int _la;
		try {
			EnterOuterAlt(_localctx, 1);
			{
			State = 83;
			_la = _input.La(1);
			if ( !(_la==IntLiteral || _la==Identifier) ) {
			_errHandler.RecoverInline(this);
			} else {
				if (_input.La(1) == TokenConstants.Eof) {
					matchedEOF = true;
				}

				_errHandler.ReportMatch(this);
				Consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.ReportError(this, re);
			_errHandler.Recover(this, re);
		}
		finally {
			ExitRule();
		}
		return _localctx;
	}

	public static readonly string _serializedATN =
		"\x3\xAF6F\x8320\x479D\xB75C\x4880\x1605\x191C\xAB37\x3\xEX\x4\x2\t\x2"+
		"\x4\x3\t\x3\x4\x4\t\x4\x4\x5\t\x5\x4\x6\t\x6\x4\a\t\a\x4\b\t\b\x4\t\t"+
		"\t\x4\n\t\n\x3\x2\a\x2\x16\n\x2\f\x2\xE\x2\x19\v\x2\x3\x2\x3\x2\x3\x3"+
		"\a\x3\x1E\n\x3\f\x3\xE\x3!\v\x3\x3\x3\x3\x3\x5\x3%\n\x3\x3\x3\a\x3(\n"+
		"\x3\f\x3\xE\x3+\v\x3\x3\x4\x3\x4\x3\x4\x3\x4\x5\x4\x31\n\x4\x3\x4\x3\x4"+
		"\x3\x4\x3\x5\x3\x5\x3\x5\x3\x5\x3\x6\x3\x6\x3\x6\x3\x6\x5\x6>\n\x6\x3"+
		"\x6\x3\x6\x3\x6\x3\a\x3\a\x3\b\x3\b\a\bG\n\b\f\b\xE\bJ\v\b\x3\t\x3\t\x3"+
		"\t\a\tO\n\t\f\t\xE\tR\v\t\x3\t\x3\t\x3\n\x3\n\x3\n\x2\x2\x2\v\x2\x2\x4"+
		"\x2\x6\x2\b\x2\n\x2\f\x2\xE\x2\x10\x2\x12\x2\x2\x4\x4\x2\b\b\v\v\x3\x2"+
		"\v\fW\x2\x17\x3\x2\x2\x2\x4\x1F\x3\x2\x2\x2\x6,\x3\x2\x2\x2\b\x35\x3\x2"+
		"\x2\x2\n\x39\x3\x2\x2\x2\f\x42\x3\x2\x2\x2\xEH\x3\x2\x2\x2\x10K\x3\x2"+
		"\x2\x2\x12U\x3\x2\x2\x2\x14\x16\x5\x4\x3\x2\x15\x14\x3\x2\x2\x2\x16\x19"+
		"\x3\x2\x2\x2\x17\x15\x3\x2\x2\x2\x17\x18\x3\x2\x2\x2\x18\x1A\x3\x2\x2"+
		"\x2\x19\x17\x3\x2\x2\x2\x1A\x1B\a\x2\x2\x3\x1B\x3\x3\x2\x2\x2\x1C\x1E"+
		"\a\x5\x2\x2\x1D\x1C\x3\x2\x2\x2\x1E!\x3\x2\x2\x2\x1F\x1D\x3\x2\x2\x2\x1F"+
		" \x3\x2\x2\x2 $\x3\x2\x2\x2!\x1F\x3\x2\x2\x2\"%\x5\x6\x4\x2#%\x5\n\x6"+
		"\x2$\"\x3\x2\x2\x2$#\x3\x2\x2\x2%)\x3\x2\x2\x2&(\a\x5\x2\x2\'&\x3\x2\x2"+
		"\x2(+\x3\x2\x2\x2)\'\x3\x2\x2\x2)*\x3\x2\x2\x2*\x5\x3\x2\x2\x2+)\x3\x2"+
		"\x2\x2,-\a\x3\x2\x2-.\a\x6\x2\x2.\x30\a\f\x2\x2/\x31\x5\b\x5\x2\x30/\x3"+
		"\x2\x2\x2\x30\x31\x3\x2\x2\x2\x31\x32\x3\x2\x2\x2\x32\x33\a\t\x2\x2\x33"+
		"\x34\x5\xE\b\x2\x34\a\x3\x2\x2\x2\x35\x36\a\n\x2\x2\x36\x37\x5\xE\b\x2"+
		"\x37\x38\a\x4\x2\x2\x38\t\x3\x2\x2\x2\x39:\a\x3\x2\x2:;\a\a\x2\x2;=\a"+
		"\f\x2\x2<>\x5\f\a\x2=<\x3\x2\x2\x2=>\x3\x2\x2\x2>?\x3\x2\x2\x2?@\a\t\x2"+
		"\x2@\x41\x5\xE\b\x2\x41\v\x3\x2\x2\x2\x42\x43\t\x2\x2\x2\x43\r\x3\x2\x2"+
		"\x2\x44G\x5\x10\t\x2\x45G\a\x5\x2\x2\x46\x44\x3\x2\x2\x2\x46\x45\x3\x2"+
		"\x2\x2GJ\x3\x2\x2\x2H\x46\x3\x2\x2\x2HI\x3\x2\x2\x2I\xF\x3\x2\x2\x2JH"+
		"\x3\x2\x2\x2KL\a\x3\x2\x2LP\a\f\x2\x2MO\x5\x12\n\x2NM\x3\x2\x2\x2OR\x3"+
		"\x2\x2\x2PN\x3\x2\x2\x2PQ\x3\x2\x2\x2QS\x3\x2\x2\x2RP\x3\x2\x2\x2ST\a"+
		"\t\x2\x2T\x11\x3\x2\x2\x2UV\t\x3\x2\x2V\x13\x3\x2\x2\x2\v\x17\x1F$)\x30"+
		"=\x46HP";
	public static readonly ATN _ATN =
		new ATNDeserializer().Deserialize(_serializedATN.ToCharArray());
}
} // namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser
