lexer grammar MessageScriptLexer;

////////////////////
//
// Lexer rules
//
////////////////////

//
// Text lexer rules
//

OpenCode
	: '[' -> pushMode( MessageScriptCode );

CloseText
	: ']' -> pushMode( MessageScriptCode );  // close tag is used for closing inline text inside tag

Text
	: ~( '[' | ']' )+?;

//
// Code lexer rules
//
mode MessageScriptCode;

MessageDialogTagId
	: 'msg'
	| 'dlg'
	;

SelectionDialogTagId
	: 'sel';

// Keywords
CloseCode
	: ']' -> popMode;

OpenText
	: '[' -> popMode;  // open tag is used for opening inline text inside tag

// Literals

// This must come before identifier, otherwise some integers 
// will get mistaken for an identifier
IntLiteral
	: ( DecIntLiteral | HexIntLiteral );

Identifier
	: ( Letter | Digit | '_' | '-' )+;

fragment
DecIntLiteral
	: Sign? Digit+;

fragment
HexIntLiteral
	: Sign? HexLiteralPrefix HexDigit+;

fragment
Letter
	: ( [a-zA-Z] | JapaneseCharacter );

fragment
JapaneseCharacter
	: ( KanjiCharacter | HiraganaCharacter | KatakanaCharacter | '\u3001' | '\u30FC' | '\u3005' | '\u3006' | '\u3024' | '\uFF1C' | '\uFF1E' );

fragment
KanjiCharacter
	: [\u4E00-\u9FA0];

fragment
HiraganaCharacter
	: [\u3041-\u30F4];

fragment
KatakanaCharacter
	: [\u30A1-\u30F4];

fragment
Digit
	: [0-9];

fragment
HexDigit
	: ( Digit | [a-fA-F] );

fragment
HexLiteralPrefix
	: '0' [xX];

fragment
Sign
	: '+' | '-';

Whitespace
	: [ \t\r\n] -> skip;
