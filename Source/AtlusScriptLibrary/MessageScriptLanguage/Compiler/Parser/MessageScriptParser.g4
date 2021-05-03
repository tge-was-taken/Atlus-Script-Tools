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
	: dialog* EOF
	;
	
dialog
	: ( LineComment | EmptyLine )* ( messageDialog | selectionDialog )
	;

	// [ msg DialogName [SpeakerName] ] text...
messageDialog
	: OpenCode MessageDialogTagId Identifier speakerName? CloseCode tokenText
	;

speakerName
	: OpenText tokenText CloseText
	;

	// [ sel SelectionName ] text...
selectionDialog
	: OpenCode SelectionDialogTagId Identifier CloseCode tokenText
	;

tokenText
	: ( token | Text )*
	;

token
	: OpenCode Identifier expression* CloseCode
	;

expression
	: IntLiteral
	| Identifier
	;
