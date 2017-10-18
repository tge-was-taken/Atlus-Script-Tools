grammar FlowScript;

//////////////////
//
// Parser rules
//
//////////////////

// Basic constructs
compilationUnit
	: importStatement* statement* EOF
	;

importStatement
	: 'import' StringLiteral ';'
	;

statement
	: nullStatement
	| compoundStatement
	| declarationStatement
	| expression ';'
	| ifStatement
	| forStatement
	| whileStatement
	| breakStatement
	| continueStatement
	| returnStatement
	| gotoStatement
	;

nullStatement
	: ';'
	;

compoundStatement
	: '{' statement* '}'
	//| statement
	;

//
// Declaration statements
//
declarationStatement
	: functionDeclarationStatement
	| procedureDeclarationStatement
	| variableDeclarationStatement
	| labelDeclarationStatement
	;

functionDeclarationStatement
	: Function'('IntLiteral')' TypeIdentifier Identifier parameterList ';'
	;

procedureDeclarationStatement
	: TypeIdentifier Identifier parameterList compoundStatement
	;

variableDeclarationStatement
	: variableModifier? TypeIdentifier Identifier ('=' expression)? ';'
	;

labelDeclarationStatement
	: Identifier ':'
	;

variableModifier
	: Static
	| Const
	;

//
// Parameters
//
parameterList
	: '(' parameter? (',' parameter)* ')'
	;

parameter
	: TypeIdentifier Identifier
	;

//
// Expressions
//
expressionList
	: '(' (expression)? (',' expression)* ')'
	;

expression
	: ';'															# nullExpression
	| '(' expression ')'											# compoundExpression
	| TypeIdentifier '(' expression ')'								# castExpression				// precedence 2
	| Identifier expressionList										# callExpression				// precedence 2
	| expression Op=( '--' | '++' )									# unaryPostfixExpression		// precedence 2
	| Op=( '!' | '-' | '--' | '++' ) expression						# unaryPrefixExpression			// precedence 3
	| expression Op=( '*' | '/' ) expression						# multiplicationExpression		// precedence 5
	| expression Op=( '+' | '-' ) expression						# additionExpression			// precedence 6
	| expression Op=( '<' | '>' | '<=' | '>=' ) expression			# relationalExpression			// precedence 8
	| expression Op=( '==' | '!=' ) expression						# equalityExpression			// precedence 9	
	| expression '&&' expression									# logicalAndExpression			// precedence 13
	| expression '||' expression									# logicalOrExpression			// precedence 14
	| Identifier Op=( '=' | '+=' | '-=' | '*=' | '/=' ) expression	# assignmentExpression			// precedence 15
	| primary														# primaryExpression
	;

primary
	: constant		# constantExpression
	| Identifier	# identifierExpression
	;

constant
	: BoolLiteral
	| IntLiteral
	| FloatLiteral
	| StringLiteral
	;

//
// Flow control statements
//
ifStatement
	: If '(' expression ')' statement (Else statement)*
	;

// not perfect
forStatement
	: For '(' statement expression ';' expression ')' statement
	;

whileStatement
	: While expression statement
	;

breakStatement
	: Break ';'
	;

continueStatement
	: Continue ';'
	;

returnStatement
	: Return expression? ';'
	;

gotoStatement
	: Goto Identifier ';'
	;

////////////////////
//
// Lexer rules
//
////////////////////

// Keywords
Function:	'function';
Static:		'static';
Const:		'const';
If:			'if';
Else:		'else';
For:		'for';
While:		'while';
Break:		'break';
Continue:	'continue';
Return:		'return';
Goto:		'goto';

TypeIdentifier
	: 'bool'
	| 'int'
	| 'float'
	| 'string'
	| 'void'
	;

// Literals

// Boolean constants
BoolLiteral
	: ( True | False )
	;

fragment
True:		'true';

fragment
False:		'false';

// Integer constants
IntLiteral
	: ( DecIntLiteral | HexIntLiteral );

fragment
DecIntLiteral
	: Sign? Digit+;

fragment
HexIntLiteral
	: Sign? HexLiteralPrefix HexDigit+;

// Float constant
FloatLiteral
	//: Sign? Digit+ '.'? Digit* FloatLiteralSuffix?;
	: Sign? Digit* '.'? Digit+ ( FloatLiteralExponent Sign? Digit+ )? FloatLiteralSuffix?
	;

fragment
FloatLiteralSuffix
	: ( 'f' | 'F' )
	;

fragment
FloatLiteralExponent
	: ( 'e' | 'E' )
	;

// String constant
StringLiteral
	: '"' ( StringEscapeSequence | ~( '\\' | '"' ) )* '"'
	;

fragment
StringEscapeSequence
    : '\\' ( [abfnrtvz"'] | '\\' )
    | '\\' '\r'? '\n'
    | StringDecimalEscape
    | StringHexEscape
    ;
    
fragment
StringDecimalEscape
    : '\\' Digit
    | '\\' Digit Digit
    | '\\' [0-2] Digit Digit
    ;
    
fragment
StringHexEscape
    : '\\' 'x' HexDigit HexDigit;

// Identifiers
Identifier
	: LetterOrUnderscore LetterOrUnderscoreOrDigit*;

fragment
Letter
	: [a-zA-Z];

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

fragment
LetterOrUnderscore
	: ( Letter | '_' );

fragment
LetterOrUnderscoreOrDigit
	: ( LetterOrUnderscore | Digit );



// Whitespace, newline & comments
Whitespace
    :   [ \t]+
        -> skip
    ;

Newline
    :   (   '\r' '\n'?
        |   '\n'
        )
        -> skip
    ;

BlockComment
    :   '/*' .*? '*/'
        -> skip
    ;

LineComment
    :   '//' ~( '\r' | '\n' )*
        -> skip
    ;
