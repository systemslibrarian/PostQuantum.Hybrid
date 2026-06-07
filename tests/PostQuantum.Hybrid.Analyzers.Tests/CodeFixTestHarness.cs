using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers.Tests;

/// <summary>
/// In-memory harness for exercising a CodeFixProvider against the
/// diagnostics produced by an analyzer. Returns the source text after
/// applying the first registered code action for the first diagnostic
/// matching <paramref name="diagnosticId"/>.
/// </summary>
internal static class CodeFixTestHarness
{
    public static async Task<string> ApplyFixAsync(
        DiagnosticAnalyzer analyzer,
        CodeFixProvider codeFix,
        string diagnosticId,
        string code,
        params MetadataReference[] additionalReferences)
    {
        var workspace = new AdhocWorkspace();
        var projectId = ProjectId.CreateNewId();
        var documentId = DocumentId.CreateNewId(projectId);

        var references = new List<MetadataReference>
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
        };
        var trustedPlatformAssemblies = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")) ?? string.Empty;
        foreach (var path in trustedPlatformAssemblies.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (File.Exists(path))
            {
                references.Add(MetadataReference.CreateFromFile(path));
            }
        }
        references.AddRange(additionalReferences);

        var projectInfo = ProjectInfo.Create(
            projectId,
            VersionStamp.Create(),
            name: "Test",
            assemblyName: "Test",
            language: LanguageNames.CSharp,
            metadataReferences: references,
            compilationOptions: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var solution = workspace.CurrentSolution
            .AddProject(projectInfo)
            .AddDocument(documentId, "Test.cs", code);

        var document = solution.GetDocument(documentId)!;
        var compilation = await document.Project.GetCompilationAsync();
        var withAnalyzers = compilation!.WithAnalyzers(ImmutableArray.Create(analyzer));
        var diagnostics = await withAnalyzers.GetAnalyzerDiagnosticsAsync();
        var diagnostic = diagnostics.FirstOrDefault(d => d.Id == diagnosticId)
            ?? throw new InvalidOperationException(
                $"No diagnostic with id {diagnosticId} produced. Found: {string.Join(", ", diagnostics.Select(d => d.Id))}");

        CodeAction? selectedAction = null;
        var context = new CodeFixContext(
            document,
            diagnostic,
            registerCodeFix: (action, _) => selectedAction ??= action,
            cancellationToken: default);
        await codeFix.RegisterCodeFixesAsync(context);

        if (selectedAction is null)
        {
            throw new InvalidOperationException("Code fix provider did not register any action.");
        }

        var operations = await selectedAction.GetOperationsAsync(default);
        var applyOperation = operations.OfType<ApplyChangesOperation>().First();
        var changedDocument = applyOperation.ChangedSolution.GetDocument(documentId)!;
        var changedText = await changedDocument.GetTextAsync();
        return changedText.ToString();
    }
}
