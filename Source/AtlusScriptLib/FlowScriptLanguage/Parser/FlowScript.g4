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

compoundStatement
	: '{' statement* '}'
	| statement
	;

statement
	: ';' // empty statement
	| declarationStatement
	| expression ';'
	| ifStatement
	| forStatement
	| whileStatement
	| breakStatement
	| continueStatement
	| returnStatement
	;

// declarations
declarationStatement
	: functionDeclarationStatement
	| procedureDeclarationStatement
	| variableDeclarationStatement
	;

functionDeclarationStatement
	: TypeIdentifier Func'('IntLiteral')' Identifier parameterList ';'
	;

procedureDeclarationStatement
	: TypeIdentifier Identifier parameterList ( compoundStatement? | ';' )
	;

variableDeclarationStatement
	: Local? TypeIdentifier Identifier ('=' expression)? ';'
	;

parameterList
	: '(' parameter? (',' parameter)* ')'
	;

parameter
	: TypeIdentifier Identifier
	;

expressionList
	: '(' (expression)? (',' expression)* ')'
	;

expression
	: ';'													# nullExpression
	| '(' expression ')'									# compoundExpression
	| TypeIdentifier '(' expression ')'						# castExpression				// precedence 2
	| Identifier expressionList								# callExpression				// precedence 2
	| expression Op=( '--' | '++' )							# unaryPostfixExpression		// precedence 2
	| Op=( '~' | '!' | '-' | '--' | '++' ) expression		# unaryPrefixExpression			// precedence 3
	| expression Op=( '*' | '/' ) expression				# multiplicationExpression		// precedence 5
	| expression Op=( '+' | '-' ) expression				# additionExpression			// precedence 6
	| expression Op=( '<' | '>' | '=<' | '>=' ) expression	# relationalExpression			// precedence 8
	| expression Op=( '==' | '!=' ) expression				# equalityExpression			// precedence 9	
	| expression '&&' expression							# logicalAndExpression			// precedence 13
	| expression '||' expression							# logicalOrExpression			// precedence 14
	| Identifier '=' expression								# assignmentExpression			// precedence 15
	| primary												# primaryExpression
	;

// operators
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

ifStatement
	: If expression compoundStatement (Else ifStatement)* (Else compoundStatement)?
	;

// not perfect
forStatement
	: For '(' statement expression ';' expression ')' compoundStatement
	;

whileStatement
	: While expression compoundStatement
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

////////////////////
//
// Lexer rules
//
////////////////////

// Keywords
Func:		'func';
Local:		'local';
If:			'if';
Else:		'else';
For:		'for';
While:		'while';
Break:		'break';
Continue:	'continue';
Return:		'return';

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
