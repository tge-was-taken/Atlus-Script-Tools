
# Atlus Script Tools [![Build status](https://github.com/tge-was-taken/Atlus-Script-Tools/actions/workflows/ci.yml/badge.svg)](https://github.com/tge-was-taken/Atlus-Script-Tools/actions/workflows/ci.yml)

Set of tools developed for handling Atlus' script formats including
* flow script files (.bf)
* message script files (.bmd, .bm2)

All of the code is written in C# and licensed under the GNU GPL.

Latest build:
* [Github release](https://github.com/tge-was-taken/Atlus-Script-Tools/releases), published for every master build: a native archive per platform, plus a portable build that needs an installed .NET runtime
* [CI artifacts](https://github.com/tge-was-taken/Atlus-Script-Tools/actions/workflows/ci.yml) for branch builds, kept for 90 days

### Matching decompilation ###

`-Matching` makes the decompiler record binary details that the bytecode does not imply, so that
recompiling its output reproduces the original file byte for byte. A header comment names the
versions the original was read as, and `pragma()` statements carry the details the compiler needs:

```c
//
// FlowScript decompiled using Atlus Script Tools
// Original binary: FlowScript Version1, embedded MessageScript Version1DDS (MSG0)
//

pragma("omit-empty-string-section");
pragma("msg-version", 0);

import("in.msg");
```

`pragma()` takes an option name and an optional value, and sits with the imports at the top of a
file. It is not a keyword: a script that uses `pragma` as a name of its own still compiles, and an
unknown option is an error rather than something silently ignored.

`omit-empty-string-section` means the original leaves the String section out rather than writing
the reserved empty one. `msg-version 0` means the embedded MessageScript is an MSG0 file, which
the output format cannot say: both MSG0 and MSG1 files exist within one game and one
`-OutFormat`, so it is a property of the file.

A pragma that does not fit what is being compiled is ignored with a warning rather than applied,
so editing a decompiled script cannot produce a broken file. `omit-empty-string-section` is
dropped once the script pushes a string, since a `PUSHSTR` operand indexes that section, and
`msg-version 0` is dropped unless the embedded MessageScript is written in the Digital Devil Saga
layout, the only one MSG0 is known from.

## Using the library ##

`AtlusScriptLibrary` is published as a NuGet package, targeting `net10.0` and `netstandard2.0`:

```
dotnet add package AtlusScriptLibrary
```

The `Charsets` and `Libraries` data files come with the package and are copied next to your
binary, since they are read from disk at runtime.

```csharp
var library = LibraryLookup.GetLibrary("raidou2");
var script = FlowScript.FromFile("field.bf");
```

## Supported games ##
* Catherine
* Catherine: Full Body
* Devil Summoner: Raidou Kuzunoha vs. the Soulless Army
* Devil Summoner 2: Raidou Kuzunoha vs. King Abaddon
* Persona 3
* Persona 3 FES
* Persona 3 Portable
* Persona 3 Reload
* Persona 4
* Persona 4 Golden
* Persona 5
* Persona 5 Royal
* Persona Q
* Persona Q2: New Cinema Labyrinth
* Shin Megami Tensei 3: Nocturne
* Shin Megami Tensei 3: Nocturne HD
* Shin Megami Tensei: Digital Devil Saga 1
* Shin Megami Tensei: Digital Devil Saga 2
* Trauma Center Second Opinion
* Trauma Center New Blood
* Etrian Odyssey II: Heroes of Lagaard
* Other games might be supported out-of-the-box for editing of message script files

## Example usage ##
Decompiling a script from Persona 5 Royal: ``AtlusScriptCompiler -Decompile -In "path/to/script.bf" -Library P5R -Encoding P5``

Compiling a script for SMT3: ``AtlusScriptCompiler -Compile -In "path/to/script.flow" -Library SMT3 -OutFormat V1`` 

See ``AtlusScriptCompiler -Help`` for more info.

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

## Building ##

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download). A JDK is also needed,
because the ANTLR grammars are regenerated during the build.

```
dotnet build Source/AtlusScriptTools.sln -c Release
dotnet test Source/AtlusScriptLibraryTests/AtlusScriptLibraryTests.csproj -c Release
```

`AtlusScriptLibrary` targets `net10.0` and `netstandard2.0`; everything else targets `net10.0`.

Prebuilt native binaries for Windows, Linux and macOS are attached to each release, together
with a portable build that runs on any platform with an installed .NET runtime and the library
as a NuGet package. Every push to master publishes a release tagged `v1.0-<commit>`, and pushing
a `v*` tag publishes one under that tag. A `v<major>.<minor>.<patch>` tag also pushes the
package to nuget.org, which needs a `NUGET_API_KEY` repository secret.

A portable build is published without native AOT:

```
dotnet publish Source/AtlusScriptCompiler/AtlusScriptCompiler.csproj -c Release -p:PublishAot=false --no-self-contained -o out
```

### Publishing ###

Every executable publishes as a self-contained native binary that needs no installed .NET
runtime. Pass the runtime identifier for the machine you are targeting, for example
`linux-x64`, `osx-arm64` or `win-x64`:

```
dotnet publish Source/AtlusScriptCompiler/AtlusScriptCompiler.csproj -c Release -r linux-x64 -o out
```

The `Charsets` and `Libraries` directories are copied next to the binary and are read from
there at runtime, so keep them alongside the executable when distributing it.

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
