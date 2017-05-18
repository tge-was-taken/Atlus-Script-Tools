
# AtlusScriptToolchain #

Set of tools developed for handling Atlus' script formats including
* flow script files (.bf)
* message script files (.bmd)

All of the code is written in C#

## Overview ##

### AtlusScriptLib ###
* This is the main class library of the project. All of the base functionality is implemented here.

### AtlusScriptCompiler ###
* The commandline frontend for the script compiler. This application is used for
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flow) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.asm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msg) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.asm) or from/to the  compiled format (.bmd)

### AtlusScriptEvaluator ###
* This application is used for
	* Evaluating compiled or uncompiled flow scripts (.bf & .flow) and providing statistics
	* Evaluating compiled or uncompiled message scripts (.bf & .flow) and providing statistics

### Documents ###
* This directory contains all kinds of documents to serve as documentation for the file formats, and other things

## What's finished and what isn't ##

### Finished ###
* Nothing

### Unfinished ###
* AtlusScriptCompiler
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flow) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.asm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msg) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.asm) or from/to the  compiled format (.bmd)

* AtlusScriptEvaluator
	* Evaluating compiled or uncompiled flow scripts (.bf & .flow) and providing statistics
	* Evaluating compiled or uncompiled message scripts (.bf & .flow) and providing statistics