
# Atlus Script Tools [![Build status](https://ci.appveyor.com/api/projects/status/l3p8joj4frjkn753?svg=true)](https://ci.appveyor.com/project/tge-was-taken/atlus-script-tools/build/artifacts)

WIP set of tools developed for handling Atlus' script formats including
* flow script files (.bf)
* message script files (.bmd)

All of the code is written in C# and licensed under the GNU GPL.

Latest build:
* https://ci.appveyor.com/project/tge/atlusscripttools/build/artifacts

## Overview of repository structure ##

### Source ###
* This is the source code directory of the project. This is where the main solution and its projects are.

#### AtlusScriptLibrary ####
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

### Utilities ###
* This is where misc utility programs using the library will be stored. Also serves as a reference for anyone wanting to use the library.

#### AtlusMessageScriptExtractor ####
* This application is can batch extract the text from message scripts from within various binary files. Use this is if you want a quick dump of the text from a game.

#### AtlusFlowScriptExtractor ####
* Similar to the previous program, it can batch extract scripts from within various binary files. Use this is if you want a quick reference of all the scripts used in a game.

#### AtlusFlowScriptInterpreter ####
* WIP interpreter for flow scripts. Not suitable for use yet.

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
* Decompilation and compilation of message scripts. They're both missing an implementation of function aliases, but besides that they work.
* Compilation of flow scripts. The compiler is currently able to compile some decently complex scripts, but some things still need to be worked on.

### Unfinished ###
* AtlusScriptEvaluator
	* Evaluating compiled or uncompiled flow scripts (.bf & .flow) and providing statistics such as syntax errors or stack over or underflows.
	* Evaluating compiled or uncompiled message scripts (.bmd & .msg) and providing statistics. Not sure what kind of statistics would really work here though. 
