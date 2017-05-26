using System.IO;
using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.Threading;

using AtlusScriptLib.Common;
using AtlusScriptLib.Disassemblers;
using AtlusScriptLib;
using AtlusScriptLib.Decompilers;

namespace AtlusScriptCompiler
{

    internal class Program
    {
        public static string Input { get; set; }

        public static string Output { get; set; }

        public static bool Disassemble { get; set; }

        public static bool Decompile { get; set; }

        public static bool IsWorkerThreadDone { get; set; }

        private static void Main(string[] args)
        {
#if DEBUG
            args = new[] { "-i", @"d:\users\smart\documents\visual studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptLibTests\TestResources\V3_BE.bf", "-o", @"d:\users\smart\documents\visual studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptLibTests\TestResources\V3_BE.asm", "-dis" };
#endif
            if (!InitArguments(args))
            {
                return;
            }

            if (Disassemble)
            {
                PerformDisassembly();
            }
            else if (Decompile)
            {
                PerformDecompilation();
            }

            Console.WriteLine();
            Console.WriteLine("Done.");
            Console.ReadKey();
        }

        private static bool InitArguments(string[] args)
        {
            var parser = new CommandLineArgumentParser()
            {
                Description = "--- AtlusScriptCompiler ---"
            };

            parser.AddArguments(
                new CommandLineArgument<string>("-i")
                {
                    Description = "Specifies the file <input>. Takes 1 parameter; a file path",
                    Required = true,
                    Target = new CommandLineArgumentValueTarget(typeof(Program), nameof(Input))
                },
                new CommandLineArgument<string>("-o")
                {
                    Description = "Specifies the file <output>. Takes 1 parameter; a file path",
                    Target = new CommandLineArgumentValueTarget(typeof(Program), nameof(Output))
                },
                new CommandLineArgument<bool>("-dis")
                {
                    Description = "Instructs the compiler to disassemble a script <input> and write the output to <output>",
                    TakesParameters = false,
                    Target = new CommandLineArgumentValueTarget(typeof(Program), nameof(Disassemble)),
                },
                new CommandLineArgument<bool>("-dec")
                {
                    Description = "Instructs the compiler to decompile a script <input> and write the output to <output>",
                    TakesParameters = false,
                    Target = new CommandLineArgumentValueTarget(typeof(Program), nameof(Decompile)),
                }
            );

            Console.WriteLine(parser.Description);

#if !DEBUG
            try
            {
#endif
                parser.Parse(args);
#if !DEBUG
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error occured: {e.Message}");
                Console.WriteLine();
                Console.WriteLine(parser.GetArgumentInfoString());
                Console.ReadKey();
                return false;
            }
#endif

                return true;
        }

        private static void CreateWorkerThreadAndWait(WaitCallback callback)
        {
            ThreadPool.QueueUserWorkItem(callback);

            Console.Write("Progress: ");

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var lastElapsed = stopwatch.Elapsed;
            while (!IsWorkerThreadDone)
            {
                var elapsed = stopwatch.Elapsed;

                if (elapsed.Seconds - lastElapsed.Seconds >= 1)
                    Console.Write('|');

                lastElapsed = elapsed;
            }

            stopwatch.Stop();
        }

        private static void PerformDisassembly()
        {
            if (Path.GetExtension(Input) != "bf")
            {
                Console.WriteLine("Invalid file input. Only FlowScript binaries (.bf) are supported.");
                return;
            }

            if (Output == null)
                Output = Path.ChangeExtension(Input, "asm");

            Console.WriteLine($"Disassembling {Input} to {Output}");

            CreateWorkerThreadAndWait((state) =>
            {
                using (var disassembler = new FlowScriptBinaryDisassembler(Output))
                {
                    disassembler.Disassemble(FlowScriptBinary.FromFile(Input));
                }

                IsWorkerThreadDone = true;
            });
        }

        private static void PerformDecompilation()
        {
            if (Path.GetExtension(Input).Equals(".bf", StringComparison.InvariantCultureIgnoreCase))
            {
                if (Output == null)
                    Output = Path.ChangeExtension(Input, "flow");

                Console.WriteLine($"Decompiling {Input} to {Output}");

                CreateWorkerThreadAndWait((state) =>
                {
                    using (var decompiler = new FlowScriptBinaryDecompiler(Output))
                    {
                        decompiler.Decompile(FlowScriptBinary.FromFile(Input));
                    }

                    IsWorkerThreadDone = true;
                });
            }
            else if (Path.GetExtension(Input).Equals(".bmd", StringComparison.InvariantCultureIgnoreCase))
            {
                if (Output == null)
                    Output = Path.ChangeExtension(Input, "msg");

                Console.WriteLine($"Decompiling {Input} to {Output}");

                CreateWorkerThreadAndWait((state) =>
                {
                    var decompiler = new MessageScriptDecompiler(MessageScript.FromBinary(MessageScriptBinary.FromFile(Input)));
                    decompiler.Decompile(Output);

                    IsWorkerThreadDone = true;
                });
            }
            else
            {
                Console.WriteLine("Unknown input file type");
            }
        }
    }
}
