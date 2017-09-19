parser grammar MessageScriptParser;

options 
{ 
	tokenVocab = MessageScriptLexer;
}

////////////////////
//
// Parser rules
//
////////////////////

compilationUnit
	: messageWindow* EOF
	;
	
messageWindow
	: dialogWindow | selectionWindow
	;

dialogWindow
	: OpenCode MessageDialogTagId OpenText content CloseText ( OpenText content CloseText )? CloseCode content
	;

selectionWindow
	: OpenCode SelectionDialogTagId OpenText content CloseText CloseCode content
	;

content
	: ( tag | Text )*
	;

tag
	: OpenCode TagId TagIntArgument* CloseCode
	;
