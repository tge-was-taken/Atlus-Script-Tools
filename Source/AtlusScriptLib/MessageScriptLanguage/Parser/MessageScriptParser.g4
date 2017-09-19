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

	// [ dlg DialogName [SpeakerName] ] text...
dialogWindow
	: OpenCode MessageDialogTagId Identifier dialogWindowSpeakerName? CloseCode tagText
	;

dialogWindowSpeakerName
	: OpenText tagText CloseText
	;

	// [ sel SelectionName ] text...
selectionWindow
	: OpenCode SelectionDialogTagId Identifier CloseCode tagText
	;

tagText
	: ( tag | Text )*
	;

tag
	: OpenCode Identifier IntLiteral* CloseCode
	;
