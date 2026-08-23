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
/// Quick-fix for PQH002: replace a raw <c>.SharedSecret</c> argument with
/// <c>HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt: null, info: ...)</c>
/// so the KEM secret feeds the symmetric primitive through a KDF instead
/// of directly. The "info" parameter is left as a TODO literal that the
/// developer fills in with a purpose-specific label.
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(HkdfWrapSharedSecretCodeFix)), Shared]
public sealed class HkdfWrapSharedSecretCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create(SharedSecretWithoutHkdfAnalyzer.DiagnosticId);

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
            var node = root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true);
            var outerExpression = node as ExpressionSyntax
                ?? node.AncestorsAndSelf().OfType<ExpressionSyntax>().FirstOrDefault();
            if (outerExpression is null)
            {
                continue;
            }

            var innerSharedSecret = FindInnerSharedSecretAccess(outerExpression);
            if (innerSharedSecret is null)
            {
                continue;
            }

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: "Wrap with HKDF.DeriveKey",
                    createChangedDocument: ct => WrapAsync(context.Document, outerExpression, innerSharedSecret, ct),
                    equivalenceKey: "PQH002:hkdf-wrap"),
                diagnostic);
        }
    }

    private static MemberAccessExpressionSyntax? FindInnerSharedSecretAccess(ExpressionSyntax expr)
    {
        // Walk through .AsSpan() / .ToArray() / .AsMemory() to find the underlying ".SharedSecret".
        while (expr is InvocationExpressionSyntax invocation
            && invocation.Expression is MemberAccessExpressionSyntax invokedMember
            && (invokedMember.Name.Identifier.Text == "AsSpan"
                || invokedMember.Name.Identifier.Text == "ToArray"
                || invokedMember.Name.Identifier.Text == "AsMemory"))
        {
            expr = invokedMember.Expression;
        }

        if (expr is MemberAccessExpressionSyntax member
            && member.Name.Identifier.Text == "SharedSecret")
        {
            return member;
        }
        return null;
    }

    private static async Task<Document> WrapAsync(
        Document document,
        ExpressionSyntax outerExpression,
        MemberAccessExpressionSyntax innerSharedSecret,
        CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return document;
        }

        // HKDF.DeriveKey(
        //     HashAlgorithmName.SHA256,
        //     <enc>.SharedSecret,
        //     32,
        //     salt: null,
        //     info: System.Text.Encoding.UTF8.GetBytes("TODO: purpose"))
        var deriveCall = SyntaxFactory.InvocationExpression(
            SyntaxFactory.ParseExpression("System.Security.Cryptography.HKDF.DeriveKey"),
            SyntaxFactory.ArgumentList(SyntaxFactory.SeparatedList(new[]
            {
                SyntaxFactory.Argument(SyntaxFactory.ParseExpression(
                    "System.Security.Cryptography.HashAlgorithmName.SHA256")),
                SyntaxFactory.Argument(innerSharedSecret.WithoutTrivia()),
                SyntaxFactory.Argument(SyntaxFactory.LiteralExpression(
                    SyntaxKind.NumericLiteralExpression,
                    SyntaxFactory.Literal(32))),
                SyntaxFactory.Argument(SyntaxFactory.LiteralExpression(SyntaxKind.NullLiteralExpression))
                    .WithNameColon(SyntaxFactory.NameColon("salt")),
                SyntaxFactory.Argument(SyntaxFactory.ParseExpression(
                    "System.Text.Encoding.UTF8.GetBytes(\"TODO: purpose-specific info\")"))
                    .WithNameColon(SyntaxFactory.NameColon("info")),
            })))
            .WithTriviaFrom(outerExpression);

        var newRoot = root.ReplaceNode(outerExpression, deriveCall);
        return document.WithSyntaxRoot(newRoot);
    }
}
