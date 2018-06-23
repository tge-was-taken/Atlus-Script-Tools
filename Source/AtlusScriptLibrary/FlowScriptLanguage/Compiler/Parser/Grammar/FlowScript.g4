grammar FlowScript;

//////////////////
//
// Parser rules
//
//////////////////

// Basic constructs
compilationUnit
	: importStatement* declarationStatement* EOF
	;

importStatement
	: Import '(' StringLiteral ')' ';'
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
	| switchStatement
	;

nullStatement
	: ';'
	;

compoundStatement
	: '{' statement* '}'
	;

//
// Declaration statements
//
declarationStatement
	: functionDeclarationStatement
	| procedureDeclarationStatement
	| variableDeclarationStatement
	| enumTypeDeclarationStatement
	| labelDeclarationStatement
	;

functionDeclarationStatement
	: Function'('IntLiteral')' ( PrimitiveTypeIdentifier | Identifier ) Identifier parameterList ';'
	;

procedureDeclarationStatement
	: ( PrimitiveTypeIdentifier | Identifier ) ( Identifier | ProcedureIdentifier ) parameterList compoundStatement
	;

variableDeclarationStatement
	: variableModifier? ( PrimitiveTypeIdentifier | Identifier ) Identifier arraySignifier? ('=' expression)? ';'
	;

arraySignifier
	: ('[' IntLiteral? ']')
	;

enumTypeDeclarationStatement
	: Enum Identifier enumValueList
	;

enumValueDeclaration
	: Identifier ( '=' expression )?
	;

enumValueList
	: '{' enumValueDeclaration? ( enumValueDeclaration ',' )* ( enumValueDeclaration ','? )? '}'
	;

labelDeclarationStatement
	: Identifier ':'
	;

variableModifier
	: Global ('('IntLiteral')')?
	| Const
	| AiLocal ('('IntLiteral')')?
	| AiGlobal ('('IntLiteral')')?
	| Bit ('('IntLiteral')')
	;

//
// Parameters
//
parameterList
	: '(' parameter? (',' parameter)* ')'
	;

parameter
	: Out? ( PrimitiveTypeIdentifier | Identifier ) Identifier arraySignifier?
	;

//
// Arguments
//
argumentList
	: '(' argument? (',' argument)* ')'
	;

argument
	: expression
	| Out Identifier
	;

//
// Expressions
//
expressionList
	: '(' (expression)? (',' expression)* ')'
	;

expression
	: ';'																	# nullExpression
	| '(' expression ')'													# compoundExpression
	| '{' (expression)? (',' expression)* (',')? '}'						# initializerListExpression
	| Identifier '[' expression ']'											# subscriptExpression
	| Identifier '.' Identifier												# memberAccessExpression
	| '(' ( PrimitiveTypeIdentifier | Identifier ) ')' '(' expression ')'	# castExpression				// precedence 2
	| Identifier argumentList												# callExpression				// precedence 2
	| expression Op=( '--' | '++' )											# unaryPostfixExpression		// precedence 2
	| Op=( '!' | '-' | '--' | '++' ) expression								# unaryPrefixExpression			// precedence 3
	| expression Op=( '*' | '/' | '%' ) expression							# multiplicationExpression		// precedence 5
	| expression Op=( '+' | '-' ) expression								# additionExpression			// precedence 6
	| expression Op=( '<' | '>' | '<=' | '>=' ) expression					# relationalExpression			// precedence 8
	| expression Op=( '==' | '!=' ) expression								# equalityExpression			// precedence 9	
	| expression '&&' expression											# logicalAndExpression			// precedence 13
	| expression '||' expression											# logicalOrExpression			// precedence 14
	| expression Op=( '=' | '+=' | '-=' | '*=' | '/=' | '%=') expression	# assignmentExpression			// precedence 15
	| primary																# primaryExpression
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
	| Goto Case expression ';'
	| Goto Case Default ';'
	;

switchStatement
	: Switch '(' expression ')' '{' switchLabel+ '}'
	;

switchLabel
	: Case expression ':' statement*
	| Default ':' statement*
	;

////////////////////
//
// Lexer rules
//
////////////////////

// Keywords
//	Directives
Import:		'import';

//	Storage types
Function:	'function';
Global:		'global';
Const:		'const';
AiLocal:	'ai_local';
AiGlobal:	'ai_global';
Bit:		'bit';
Enum:		'enum';
Out:		'out';

//	Control flow
If:			'if';
Else:		'else';
For:		'for';
While:		'while';
Break:		'break';
Continue:	'continue';
Return:		'return';
Goto:		'goto';
Switch:		'switch';
Case:		'case';
Default:	'default';

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
 
PrimitiveTypeIdentifier
	: 'bool'
	| 'int'
	| 'float'
	| 'string'
	| 'void'
	;

ProcedureIdentifier
	: LetterOrUnderscoreOrDigit LetterOrUnderscoreOrDigit*;

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
	: ( Letter | '_' | Digit );


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
