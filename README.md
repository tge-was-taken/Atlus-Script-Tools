
# AtlusScriptToolchain #

WIP set of tools developed for handling Atlus' script formats including
* flow script files (.bf)
* message script files (.bmd)

All of the code is written in C# and licensed under the GNU GPL.

## Overview of repository structure ##

### Source ###
* This is the source code directory of the project. This is where the main solution and its projects are.

#### AtlusScriptLib ####
* This is the main class library of the project. All of the core functionality will be implemented here, with the other programs serving as a front-end.

#### AtlusScriptCompiler ####
* The commandline frontend for the script compiler. This application is used for
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flow) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.asm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msg) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.asm) or from/to the  compiled format (.bmd)

#### AtlusScriptEvaluator ####
* This application is used for
	* Evaluating compiled or uncompiled flow scripts (.bf & .flow) and providing statistics
	* Evaluating compiled or uncompiled message scripts (.bf & .flow) and providing statistics

#### packages ####
* Nuget packages.

### Documents ###
* This directory contains all kinds of documents to serve as documentation for the file formats, and other things such as reversed engineered game code.

### Scripts ###
* This is where any misc. scripts will be stored, for the sake of keeping everything safe from being lost. ¯\_(ツ)_/¯

### Build ###
* Not visible on the repo but this is where all of the binaries will compile to.

## What's finished? ##

### Finished ###
* Reading and writing of flow & message script files.
* Simplified representation of both flow & message script files.

### Somewhere inbetween ###
* AtlusScriptCompiler can currently decompile message scripts, however it's still being worked on.
* Progress has been made on decompiling the flow scripts, but it's still in a conceptual phase and needs polishing.

### Unfinished ###
* AtlusScriptCompiler
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flow) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.asm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msg) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.asm) or from/to the compiled format (.bmd)

* AtlusScriptEvaluator
	* Evaluating compiled or uncompiled flow scripts (.bf & .flow) and providing statistics such as syntax errors or stack overflows.
	* Evaluating compiled or uncompiled message scripts (.bmd & .msg) and providing statistics. Not sure what kind of statistics would really work here though. 