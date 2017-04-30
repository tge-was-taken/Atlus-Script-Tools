
# AtlusScriptToolchain #

Set of tools developed for dealing with Atlus' script formats including
* flow script files (.bf)
* message script files (.bmd)

All of the code is written in C#

## Overview ##

### AtlusScriptLib ###
* This is where all of the script manipulation code for each of the tools is located

### AtlusScriptCompiler ###
* This application is used for
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flwscr) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.flwasm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msgscr) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.msgasm) or from/to the  compiled format (.bmd)

### AtlusScriptEvaluator ###
* This application is used for
	* Evaluating compiled or uncompiled flow scripts (.bf & .flwscr) and providing statistics
	* Evaluating compiled or uncompiled message scripts (.bf & .flwscr) and providing statistics

### Documents ###
* This directory contains all kinds of documents to serve as documentation for the file formats, and other things

## What's finished and what isn't ##

### Finished ###
* Nothing

### Unfinished ###
* AtlusScriptCompiler
	* Compiling & decompiling flow scripts from/to the uncompiled format (.flwscr) or from/to compiled format (.bf)
	* Compiling & decompiling flow bytecode code from/to the uncompiled format (.flwasm) or from/to the compiled format (.bf)
	* Compiling & decompiling message scripts from/to the uncompiled format (.msgscr) or from/to the compiled format (.bmd)
	* Compiling & decompiling message bytecode from/to the uncompiled format (.msgasm) or from/to the  compiled format (.bmd)

* AtlusScriptEvaluator
	* Evaluating compiled or uncompiled flow scripts (.bf & .flwscr) and providing statistics
	* Evaluating compiled or uncompiled message scripts (.bf & .flwscr) and providing statistics