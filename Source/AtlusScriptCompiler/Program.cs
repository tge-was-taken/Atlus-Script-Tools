using System.IO;
using System.Diagnostics;
using System;
using System.Collections.Generic;

using AtlusScriptLib.Common;
using AtlusScriptLib.Disassemblers;
using AtlusScriptLib;
using System.Threading;

namespace AtlusScriptCompiler
{

    class Program
    {
        public static string Input { get; set; }

        public static string Output { get; set; }

        public static bool Disassemble { get; set; }

        public static bool IsWorkerThreadDone { get; set; }

        static void Main(string[] args)
        {
#if DEBUG
            args = new string[] { "-i", @"d:\users\smart\documents\visual studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptLibTests\TestResources\V3_BE.bf", "-o", @"d:\users\smart\documents\visual studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptLibTests\TestResources\V3_BE.asm", "-dec" };
#endif
            if (!InitArguments(args))
            {
                // print help
                Console.ReadKey();
                return;
            }

            if (Disassemble)
            {
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

                Console.WriteLine();
                Console.WriteLine("Completed successfully.");
            }

            Console.ReadKey();
        }

        static void CreateWorkerThreadAndWait(WaitCallback callback)
        {
            ThreadPool.QueueUserWorkItem(callback);

            Console.Write("Progress: ");

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var lastElapsed = stopwatch.Elapsed;
            while (!IsWorkerThreadDone)
            {
                var elapsed = stopwatch.Elapsed;

                if ( (elapsed.TotalMilliseconds - lastElapsed.TotalMilliseconds) >= 2 )
                    Console.Write('|');

                lastElapsed = elapsed;
            }

            stopwatch.Stop();
        }

        static bool InitArguments(string[] args)
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
                new CommandLineArgument<bool>("-dec")
                {
                    Description = "Instruct the compiler to disassemble a script <input> and write the output to <output>",
                    TakesParameters = false,
                    Target = new CommandLineArgumentValueTarget(typeof(Program), nameof(Disassemble)),
                }
            );

            Console.WriteLine(parser.Description);

#if RELEASE
            try
            {
#endif
                parser.Parse(args);
#if RELEASE
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error occured: {e.Message}");
                Console.WriteLine();
                Console.WriteLine(parser.GetArgumentInfoString());
                return false;
            }
#endif

            return true;
        }
    }
}
