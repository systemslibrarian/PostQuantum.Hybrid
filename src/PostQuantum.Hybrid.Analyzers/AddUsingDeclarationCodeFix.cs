using System.Collections.Immutable;
using System.Composition;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// Quick-fix for PQH001: add the <c>using</c> modifier to a local
/// declaration of a hybrid disposable type.
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(AddUsingDeclarationCodeFix)), Shared]
public sealed class AddUsingDeclarationCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create(HybridDisposeAnalyzer.DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return;
        }

        foreach (var diagnostic in context.Diagnostics)
        {
            var identifier = root.FindToken(diagnostic.Location.SourceSpan.Start);
            var declaration = identifier.Parent?.AncestorsAndSelf().OfType<LocalDeclarationStatementSyntax>().FirstOrDefault();
            if (declaration is null)
            {
                continue;
            }

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: "Add 'using' declaration",
                    createChangedDocument: ct => AddUsingAsync(context.Document, declaration, ct),
                    equivalenceKey: "PQH001:add-using"),
                diagnostic);
        }
    }

    private static async Task<Document> AddUsingAsync(
        Document document,
        LocalDeclarationStatementSyntax declaration,
        System.Threading.CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return document;
        }

        var usingKeyword = SyntaxFactory.Token(SyntaxKind.UsingKeyword)
            .WithTrailingTrivia(SyntaxFactory.Space);
        var newDeclaration = declaration.WithUsingKeyword(usingKeyword);
        var newRoot = root.ReplaceNode(declaration, newDeclaration);
        return document.WithSyntaxRoot(newRoot);
    }
}
