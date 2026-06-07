using System.Collections.Immutable;
using System.Composition;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// Quick-fix for PQH004: wrap an ignored
/// <c>HybridSignature.Verify(...)</c> in
/// <c>if (!HybridSignature.Verify(...)) throw new CryptographicException(...);</c>
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(WrapVerifyCodeFix)), Shared]
public sealed class WrapVerifyCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create(IgnoredVerifyResultAnalyzer.DiagnosticId);

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
            var node = root.FindNode(diagnostic.Location.SourceSpan);
            var invocation = node.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
            if (invocation is null)
            {
                continue;
            }

            var statement = invocation.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
            if (statement is null)
            {
                continue;
            }

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: "Wrap in 'if (!Verify(...)) throw'",
                    createChangedDocument: ct => WrapAsync(context.Document, statement, invocation, ct),
                    equivalenceKey: "PQH004:wrap-throw"),
                diagnostic);
        }
    }

    private static async Task<Document> WrapAsync(
        Document document,
        StatementSyntax originalStatement,
        InvocationExpressionSyntax invocation,
        CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return document;
        }

        var ifStatement = SyntaxFactory.IfStatement(
            condition: SyntaxFactory.PrefixUnaryExpression(SyntaxKind.LogicalNotExpression, invocation.WithoutTrivia()),
            statement: SyntaxFactory.Block(
                SyntaxFactory.ThrowStatement(
                    SyntaxFactory.ObjectCreationExpression(
                        SyntaxFactory.ParseTypeName("System.Security.Cryptography.CryptographicException"),
                        SyntaxFactory.ArgumentList(
                            SyntaxFactory.SingletonSeparatedList(
                                SyntaxFactory.Argument(
                                    SyntaxFactory.LiteralExpression(
                                        SyntaxKind.StringLiteralExpression,
                                        SyntaxFactory.Literal("Signature verification failed."))))),
                        initializer: null))))
            .WithTriviaFrom(originalStatement);

        var newRoot = root.ReplaceNode(originalStatement, ifStatement);
        return document.WithSyntaxRoot(newRoot);
    }
}
