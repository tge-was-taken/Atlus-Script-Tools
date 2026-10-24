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
	: pragma* dialog* EOF
	;

	// [ pragma name ] a binary detail of the original file that the text does not imply.
	// [ pragma speaker Index shared? [SpeakerName] ] pins one speaker table entry.
pragma
	: OpenCode PragmaTagId Identifier IntLiteral? PragmaFlagId? speakerName? CloseCode
	;
	
dialog
	: Text* ( messageDialog | selectionDialog ) Text*
	;

	// [ msg DialogName [SpeakerName] ] text...
messageDialog
	: OpenCode MessageDialogTagId dialogName speakerName? DialogFlagId* CloseCode tokenText
	;

	// The flag and pattern words are keywords only where a flag or a pattern is expected, so a
	// dialog may still be named after one of them.
dialogName
	: Identifier
	| DialogFlagId
	| PragmaTagId
	| PragmaFlagId
	| SelectionDialogPatternId
	;

speakerName
	: OpenText tokenText CloseText
	;

	// [ sel SelectionName ] text...
selectionDialog
	: OpenCode SelectionDialogTagId dialogName selectionDialogPattern? DialogFlagId* CloseCode tokenText
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
