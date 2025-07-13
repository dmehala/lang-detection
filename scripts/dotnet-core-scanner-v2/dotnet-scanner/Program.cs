using System;
using System.Globalization;
using Mono.Cecil;
using System.Collections.Concurrent;
using PeNet;
using CsvHelper;
using CsvHelper.Configuration;

class Program
{
    private static readonly byte[] DotnetCoreSignature = new byte[]
    {
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    };

    private static readonly byte[] VarPlaceholder = new byte[]
    {
        0x33, 0x38, 0x63, 0x63, 0x38, 0x32, 0x37, 0x2d, 0x65, 0x33, 0x34, 0x66, 0x2d, 0x34, 0x34, 0x35,
        0x33, 0x2d, 0x39, 0x64, 0x66, 0x34, 0x2d, 0x31, 0x65, 0x37, 0x39, 0x36, 0x65, 0x39, 0x66, 0x31,
    };


    record InspectResult(string Image, string Framework, string Version);

    static List<string> FindImages(string rootPath)
    {
        var files = new List<string>();
        foreach (var file in GetAllFiles(rootPath))
        {
            if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                files.Add(file);
            }
        }
        // try
        // {
        //     // foreach (var file in Directory.EnumerateFiles(rootPath, "*.*", SearchOption.AllDirectories))
        //     // {
        //     //     Console.WriteLine(file);
        //     //     if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
        //     //         file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        //     //     {
        //     //         files.Add(file);
        //     //     }
        //     // }
        //     // files = Directory.EnumerateFiles(rootPath, "*.*", SearchOption.AllDirectories)
        //     //     .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
        //     //                 f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        //     //     .ToList();
        // }
        // catch (UnauthorizedAccessException) { Console.WriteLine("fuck me"); /* Skip restricted directories */ }
        // catch (Exception ex) { Console.WriteLine($"Error reading directory: {ex.Message}"); }

        return files;
    }

    static IEnumerable<string> GetAllFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var path = pending.Pop();
            string[] files = null;
            string[] dirs = null;

            try
            {
                files = Directory.GetFiles(path);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }

            if (files != null)
            {
                foreach (var file in files)
                {
                    yield return file;
                }
            }

            try
            {
                dirs = Directory.GetDirectories(path);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }

            if (dirs != null)
            {
                foreach (var dir in dirs)
                {
                    pending.Push(dir);
                }
            }
        }
    }

    static bool IsDotnetCore(string file)
    {
        try
        {
            byte[] data = File.ReadAllBytes(file);
            return data.AsSpan().IndexOf(DotnetCoreSignature) != -1
                || data.AsSpan().IndexOf(VarPlaceholder) != -1;
        }
        catch { return false; }
    }

    static string? IsDotnetFramework(string file)
    {
        try
        {
            var peFile = new PeFile(file);
            var comDirectory = peFile.ImageComDescriptor;

            if (comDirectory == null || comDirectory.MetaData == null)
                return null;

            var metadata = peFile.RawFile.ReadUInt((int)comDirectory.MetaData.VirtualAddress + 16);
            return null;
            /*if (comDirectory == null || comDirectory.MetaDataDirectory == null)
                return null;

            var metaData = peFile.RawFile.ReadBytes((int)comDirectory.MetaDataDirectory.VirtualAddress, 16);
            int versionLength = BitConverter.ToInt32(metaData, 12);

            var versionBytes = peFile.RawFile.ReadBytes((int)comDirectory.MetaDataDirectory.VirtualAddress + 16, versionLength);
            string version = Encoding.Unicode.GetString(versionBytes).Trim('\0');
            return version;*/
        }
        catch
        {
            return null;
        }
    }

    static string? GetDotnetCoreVersion(AssemblyDefinition assembly)
    {
        string? version = assembly.CustomAttributes
                                .FirstOrDefault(attr =>
                                    attr.AttributeType.FullName == "System.Runtime.Versioning.TargetFrameworkAttribute")
                                ?.ConstructorArguments[0].Value as string;

        if (version == null)
            return null;

        var parts = version.Split("Version=v");
        return parts.Length == 2 ? parts[1] : null;
    }

    static InspectResult? InspectImage(string path)
    {
        Console.WriteLine(path);
        try
        {
            if (IsDotnetCore(path))
            {
                // Check if there's an entrypoint
                var assembly = AssemblyDefinition.ReadAssembly(path);
                if (assembly.EntryPoint != null)
                {
                    string? version = GetDotnetCoreVersion(assembly);
                    return new InspectResult(path, ".NET Core", version ?? "NA");
                }
            }

            var dotnet_framework_version = IsDotnetFramework(path);
            if (dotnet_framework_version != null)
            {
                return new InspectResult(path, ".NET Framework", dotnet_framework_version);
            }
        }
        catch { }

        return null;
    }

    static void Main(string[] args)
    {
        // string drive = args.Length > 0 ? args[0] : @"C:\";
        string drive = @"F:\";
        // string drive = @"F:\workspace\sandbox\lang-detection\scripts\dotnet-core-scanner-v2\dotnet-scanner\bin";
        Console.WriteLine($"Searching for .exe/.dll files in {drive}");

        var images = FindImages(drive);
        Console.WriteLine($"Found {images.Count} files.");

        if (images.Count == 0)
            return;

        Console.WriteLine("Scanning for .NET info...");

        var results = new ConcurrentBag<InspectResult>();
        Parallel.ForEach(images, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, file =>
        {
            var result = InspectImage(file);
            if (result != null && !string.IsNullOrEmpty(result.Framework))
                results.Add(result);
        });

        Console.WriteLine("Writing results to dotnet_core_exes.csv");

        using var writer = new StreamWriter("dotnet_core_exes.csv");
        using var csv = new CsvWriter(writer, new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = true,
        });

        csv.WriteHeader<InspectResult>();
        csv.NextRecord();

        foreach (var item in results)
        {
            csv.WriteRecord(item);
            csv.NextRecord();
        }
    }
}
