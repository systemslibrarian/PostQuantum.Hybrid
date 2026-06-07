using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers.Tests;

/// <summary>
/// Minimal in-memory harness for running a single analyzer over a code
/// string and asserting the resulting diagnostic IDs / locations.
/// Avoids the heavyweight Microsoft.CodeAnalysis.Testing packages, which
/// drag in legacy framework dependencies.
/// </summary>
internal static class AnalyzerTestHarness
{
    public static async Task<IReadOnlyList<Diagnostic>> AnalyzeAsync(
        DiagnosticAnalyzer analyzer,
        string code,
        params MetadataReference[] additionalReferences)
    {
        var tree = CSharpSyntaxTree.ParseText(code);

        var references = new List<MetadataReference>
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
        };
        // .NET 8 reference assemblies — pull from the runtime path of System.Runtime.
        var trustedPlatformAssemblies = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")) ?? string.Empty;
        foreach (var path in trustedPlatformAssemblies.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (File.Exists(path))
            {
                references.Add(MetadataReference.CreateFromFile(path));
            }
        }
        references.AddRange(additionalReferences);

        var compilation = CSharpCompilation.Create(
            assemblyName: "TestAssembly",
            syntaxTrees: new[] { tree },
            references: references,
            options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var withAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create(analyzer));
        var diagnostics = await withAnalyzers.GetAnalyzerDiagnosticsAsync();
        return diagnostics;
    }
}
