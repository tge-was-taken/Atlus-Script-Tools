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
	: Text* ( messageDialog | selectionDialog ) Text*
	;

	// [ msg DialogName [SpeakerName] ] text...
messageDialog
	: OpenCode MessageDialogTagId Identifier speakerName? DialogFlagId? CloseCode tokenText
	;

speakerName
	: OpenText tokenText CloseText
	;

	// [ sel SelectionName ] text...
selectionDialog
	: OpenCode SelectionDialogTagId Identifier selectionDialogPattern? DialogFlagId? CloseCode tokenText
	;

selectionDialogPattern
	: IntLiteral
	| SelectionDialogPatternId
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
