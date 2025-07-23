using System.Globalization;
using Mono.Cecil;
using System.Collections.Concurrent;
using PeNet;
using CsvHelper;
using CsvHelper.Configuration;
using System.Reflection.PortableExecutable;
using System.Text;
using System.IO.Enumeration;

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


    record InspectResult(string Image, string Framework, string Version, string CompanyName, string LegalCopyright, string ProductName, string CertificateName);

    static IEnumerable<string> FindImages(string rootPath)
    {
        return new FileSystemEnumerable<string>(
               directory: rootPath,
               transform: (ref FileSystemEntry entry) => entry.ToFullPath(), // map FileSystemEntry to string (see FileSystemEnumerable generic argument)
               options: new EnumerationOptions()
               {
                   RecurseSubdirectories = true
               })
        {
            ShouldIncludePredicate = (ref FileSystemEntry entry) =>
            {
                var fullPath = entry.ToFullPath();
                var ext = Path.GetExtension(fullPath);
                return !entry.IsDirectory &&
                    (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".dll", StringComparison.OrdinalIgnoreCase));
            }
        };
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
    private static int RvaToFileOffset(PEReader peReader, int rva)
    {
        try
        {
            // Iterate through section headers to find the one containing the RVA
            foreach (var section in peReader.PEHeaders.SectionHeaders)
            {
                int sectionStart = section.VirtualAddress;
                int sectionEnd = sectionStart + section.VirtualSize;

                // Check if RVA falls within this section
                if (rva >= sectionStart && rva < sectionEnd)
                {
                    // Calculate file offset
                    return section.PointerToRawData + (rva - sectionStart);
                }
            }

            return -1; // RVA not found in any section
        }
        catch
        {
            return -1;
        }
    }
    public static string? IsDotnetFramework(string exePath)
    {
        try
        {
            using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
            using (var peReader = new PEReader(fs))
            {
                // Check if it's a DLL and validate exports
                // Ensure the PE file has .NET header (COM+ descriptor)
                var comDescriptor = peReader.PEHeaders.PEHeader.CorHeaderTableDirectory;
                if (comDescriptor.RelativeVirtualAddress == 0)
                {
                    return null;
                }

                // Convert COM+ descriptor RVA to file offset
                int comHeaderOffset = RvaToFileOffset(peReader, comDescriptor.RelativeVirtualAddress);
                if (comHeaderOffset == -1)
                    return null;

                // Read the COM+ header to get metadata RVA
                fs.Seek(comHeaderOffset + 8, SeekOrigin.Begin); // Metadata RVA is at offset 8
                byte[] metadataRvaBytes = new byte[4];
                fs.Read(metadataRvaBytes, 0, 4);
                uint metadataRva = BitConverter.ToUInt32(metadataRvaBytes, 0);

                // Convert metadata RVA to file offset
                int metadataFileOffset = RvaToFileOffset(peReader, (int)metadataRva);
                if (metadataFileOffset == -1)
                    return null;

                // Read version length from metadata header (offset 12)
                fs.Seek(metadataFileOffset + 12, SeekOrigin.Begin);
                byte[] versionLengthBytes = new byte[4];
                fs.Read(versionLengthBytes, 0, 4);
                uint versionLength = BitConverter.ToUInt32(versionLengthBytes, 0);

                // Read version string (offset 16)
                fs.Seek(metadataFileOffset + 16, SeekOrigin.Begin);
                byte[] versionBytes = new byte[versionLength];
                fs.Read(versionBytes, 0, (int)versionLength);

                // Convert to string and remove null terminators
                string versionStr = Encoding.UTF8.GetString(versionBytes).TrimEnd('\0');
                return versionStr;
            }
        }
        catch
        {
            return null;
        }
    }

    static string? GetDotnetCoreVersion(string path)
    {
        var assembly = AssemblyDefinition.ReadAssembly(path);
        string? version = assembly.CustomAttributes
                                .FirstOrDefault(attr =>
                                    attr.AttributeType.FullName == "System.Runtime.Versioning.TargetFrameworkAttribute")
                                ?.ConstructorArguments[0].Value as string;

        if (version == null)
            return null;

        var parts = version.Split("Version=v");
        return parts.Length == 2 ? parts[1] : null;
    }

    static bool HasEntrypoint(string path)
    {
        var assembly = AssemblyDefinition.ReadAssembly(path);
        return assembly.EntryPoint != null;
    }

    static string GetCompanyNameFromSignature(string path)
    {
        try
        {
            // Open the file as a signed CMS/PKCS#7 structure
            var fileBytes = File.ReadAllBytes(path);
            // Find the Authenticode signature (PKCS#7) in the PE file
            // This is a simplified approach using SignedCms and X509Certificate2
            // The signature is usually in the Win32 PE file's "WIN_CERTIFICATE" structure,
            // but .NET does not provide a direct API to extract it, so we use SignedCms if possible.

            // Use System.Security.Cryptography.Pkcs if available
            // Find the signature offset using Win32 structures
            // For simplicity, use X509Certificate.CreateFromSignedFile if available (Windows only)
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                var company = x509.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                if (!string.IsNullOrEmpty(company))
                    return company;
                // Try OrganizationName as fallback
                company = x509.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.DnsName, false);
                if (!string.IsNullOrEmpty(company))
                    return company;
            }
            catch
            {
                // Fallback: try to enumerate certificates using X509Certificate2Collection
                try
                {
                    var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
                    collection.Import(path);
                    foreach (var cert in collection)
                    {
                        var company = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                        if (!string.IsNullOrEmpty(company))
                            return company;
                    }
                }
                catch
                {
                    // Ignore
                }
            }
        }
        catch
        {
            // Ignore
        }
        return "Unknown";
    }


    static InspectResult? InspectImage(string path)
    {
        try
        {
            var fileVersionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            if (IsDotnetCore(path) && HasEntrypoint(path))
            {
                string? version = GetDotnetCoreVersion(path);
                return new InspectResult(path, ".NET Core", version ?? "NA", fileVersionInfo.CompanyName ?? "Unknown", fileVersionInfo.LegalCopyright ?? "Unknown", fileVersionInfo.ProductName ?? "Unknown", GetCompanyNameFromSignature(path));
            }

            var dotnet_framework_version = IsDotnetFramework(path);
            if (dotnet_framework_version != null && HasEntrypoint(path))
            {
                string? version = GetDotnetCoreVersion(path);
                return new InspectResult(path, ".NET Framework", version ?? dotnet_framework_version, fileVersionInfo.CompanyName ?? "Unknown", fileVersionInfo.LegalCopyright ?? "Unknown", fileVersionInfo.ProductName ?? "Unknown", GetCompanyNameFromSignature(path));
            }
        }
        catch { }

        return null;
    }

    static void Main(string[] args)
    {
        string drive = args.Length > 0 ? args[0] : @"C:\";
        Console.WriteLine($"Searching for .exe/.dll files in {drive}");

        Console.WriteLine("Scanning for .NET info...");

        var results = FindImages(drive)
            .AsParallel()
            .WithDegreeOfParallelism(Environment.ProcessorCount)
            .Select(InspectImage)
            .Where(result => result != null && !string.IsNullOrEmpty(result.Framework))
            .ToList();

        Console.WriteLine($"Found {results.Count} .NET applications.");

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
