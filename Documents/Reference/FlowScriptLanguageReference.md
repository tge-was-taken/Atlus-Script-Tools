
# FlowScript Language Reference Version X (Updated X/Y/Z) # 

## Intro ##
This is the language reference for FlowScript, the language used for creating scripts that interface with the game.

The name of the language was based off of the magic string used for FlowScript binaries (.bf files), "FLW0".

The language was designed to be familiar to anyone who is already familiar with C-like languages, such as C, C++, C# and so on.

To achieve this, the syntax of the language was modeled closely after that of C.

So if you're already familiar with a C-like language, it should take almost no time to get used to FlowScript.

## Syntax ##
The syntax is mostly the same as any C-like language, but with more restrictions.

### Primitive types ###

The valid primitive types are:
```
int
float
string
```

The ``string`` type can only be used as a parameter to a function.

### Identifiers ###
A valid identifier starts with a letter, and does not contain any symbols other than an underscore '_'. 

### Compilation unit ###
A single script file is called a 'compilation unit'.

A compilation unit consists out of:

	- zero or more import statements
	- zero or more statement

Note that import statements are expected to be at the top of the file!

### Imports ###
```
import "<path to file";
```

TODO

### Statement ###
A statement can be any of:

	- compound (block) statement
	- declaration
	- expression
	- flow control statement

### Compound (block) statement ###
A compound (or block) statement consists out of one or more statements enclosed by curly braces, '{' and '}' respectively.

### Declaration statement ###
A declaration statement is any kind of statement that declares either a function, procedure, variable or a label.

#### Function declaration ####

```
function( <integer literal> ) <type identifier> <identifier>( <parameter>, <parameter>, etc );
```

Example
```
// Declares a *function*, with as function index (ordinal) 3, 
// whose return type is void (nothing), and takes 1 string parameter.
//
// The function index is required for the compiler to know how to compile
// function calls that call this function.
//
// The return type 'void' means that the function doesn't return a value. 
//
// The function name can be any valid identifier (see syntax section).
//
// The parameter 'string message' indicates that the function takes 1 string parameter, named message.
// Multiple parameters are seperated by a comma.
//
function( 0x0003 ) void PUTS( string message );
```

#### Procedure declaration ####

```
<type identifier> <identifier>( <parameter>, <parameter>, etc )
```

```
// Declares a *procedure*, whose return type is void, and takes no parameters.
// Notice the distinction between function and procedure; this is because functions
// reside in the game's code while procedures are compiled into the script.
// Due to this, their semantics are similar yet different.
//
// Note: the name 'Main' holds no special meaning, nor does any variant of it.
// This is because the index or ordinal of the procedure is used to locate which
// procedure is called.
//
// Make sure to declare your procedures in the right order for the game to be able to
// locate them properly!
void Main()
{
}
```

#### Variable declaration ####

```
<type identifier> <identifier>;
<type identifier> <identifier> = <expression>;
```

Variables can be declared with or without a value.

Note that you can only initialize a variable with a value of the variable isn't declared outside of a procedure.

Example:
```
// Declare integer variable 'a' without initializing it with a value.
// Note that referencing an uninitialized variable is invalid.
int a;

// Declare integer variable 'b' with an initial value of 100.
int b = 100;

// Declare float variable 'c' with an initial value of 100.5
float c = 100.5f;

// Note that variables are scoped
void Main()
{
	int myVar = 0;

	while ( true )
	{
		int myVar = 0; // error: myVar was already declared in the current scope
	}
}
```

#### Label declaration ####
```
<identifier>:
```

Only intended to be used in decompiled code.

Used with the 'goto' statement.

### Expressions ###

In order of precedence:

#### Compound expression ####
```
( <expression> )
```

#### Cast expression ####
```
<type identifier>( <expression> )
```

#### Call expression ####
```
<identifier>( <expression>, <expression>, etc.. )
```

#### Unary postfix expressions
```
<expression>--
<expression>++
```

#### Unary prefix expressions
```
~<expression>
!<expression>
-<expression>
--<expression>
++<expression>
```

#### Multiplication expressions ####
```
<expression> * <expression>
<expression> / <expression>
```

#### Addition expressions ####
```
<expression> + <expression>
<expression> - <expression>
```

#### Relational expressions ####
```
<expression> < <expression>
<expression> > <expression>
<expression> <= <expression>
<expression> >= <expression>
```

#### Equality expressions ####
```
<expression> == <expression>
<expression> != <expression>
```

#### Logical And expression ####
```
<expression> && <expression>
```

#### Logical Or expression ####
```
<expression> || <expression>
```

#### Assignment expression ####
```
<identifier> = <expression>
```

#### Primary expressions ####
```
<bool literal> // true, false
<int literal>
<float literal>
<string literal> // delimited by quotes
<identifier>
```

### Flow Control Statements ###
Flow control statements alter the flow of code execution.

#### If statement ####

```
if ( <expression> ) <statement>
if ( <expression> ) <statement> else <statement>
```

Example:
```
if ( true )
{
	// statements...
}

// But also the shorter form, but this is only allowed if only 1 statement follows.
if ( true )
	// statement...

```

#### For statement ####

```
for ( <statement>; <expression>; <expression> ) <statement>
```

Example:
```
for ( int i = 0; i < 10; i++ )
{
	// statements...
}

// But also the shorter form, but this is only allowed if only 1 statement follows.
for ( int i = 0; i < 10; i++ )
	// statement...

```

In the context of a for loop, the ``break`` and ``continue`` statements are valid.

The break statement breaks out of the loop, and continues flow of code execution after the end of the loop.

The continue statement skips to the next iteration of the loop.

Example:
```
for ( int i = 0; i < 10; i++ )
{
	PUT( i ); // assuming PUT() prints a number to the debug log
	continue;

	// Will never be reached because the 'continue' statement before skips to the next iteration
	// But if it were reached then the loop would be terminated despite the condition.
	break;
}
```

#### While statement ####

```
while ( <expression> ) <statement>
```

Example:
```
while ( true )
{
	// statements...
}

// But also the shorter form, but this is only allowed if only 1 statement follows.
while ( true )
	// statement...

```

In the context of a while loop, the ``break`` and ``continue`` statements are valid.

The break statement breaks out of the loop, and continues flow of code execution after the end of the loop.

The continue statement skips to the next iteration of the loop.

Example:
```
int i = 0;
while ( true )
{
	PUT( i++ ); // assuming PUT() prints a number to the debug log
	continue;

	// Will never be reached because the 'continue' statement before skips to the next iteration
	// But if it were reached then the loop would be terminated despite the condition.
	break;
}
```

#### Return statement ####

```
return;
return <expression>;
```

Used to return from procedures, with or without a return value.

Procedures with a return type void do not have to have an explicit return statement, because the compiler

will insert one for you.

#### Goto statement ####

```
goto <identifier>;
```

Intended for decompiled code only. Don't use this unless you really have to.

Jumps to the label specified by identifier.

## Examples ##

### Hello World ###

```
// Declares a *function*, with as function index (ordinal) 3, 
// whose return type is void (nothing), and takes 1 string parameter.
//
// The function index is required for the compiler to know how to compile
// function calls that call this function.
//
// The return type 'void' means that the function doesn't return a value. 
//
// The function name can be any valid identifier (see syntax section).
//
// The parameter 'string message' indicates that the function takes 1 string parameter, named message.
// Multiple parameters are seperated by a comma.
//
function( 0x0003 ) void PUTS( string message );

// Declares a *procedure*, whose return type is void, and takes no parameters.
// Notice the distinction between function and procedure; this is because functions
// reside in the game's code while procedures are compiled into the script.
// Due to this, their semantics are similar yet different.
//
// Note: the name 'Main' holds no special meaning, nor does any variant of it.
// This is because the index or ordinal of the procedure is used to locate which
// procedure is called.
//
// Make sure to declare your procedures in the right order for the game to be able to
// locate them properly!
void Main()
{
	// Calls the function 'PUTS' with one string parameter; "Hello World"
	// This will print the string to the debug log output.
	PUTS( "Hello World" );
}

```
