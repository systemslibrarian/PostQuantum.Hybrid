using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// Quick-fix for PQH005: add an <c>associatedData</c> argument to the
/// flagged <c>AesGcm.Encrypt</c>/<c>Decrypt</c> call, binding the hybrid
/// KEM ciphertext into the AEAD so a swapped ciphertext breaks
/// decryption.
/// </summary>
/// <remarks>
/// The fix tries to discover a <c>HybridKemEncapsulationResult</c>
/// variable in the same method (for the encap flow) or the ciphertext
/// argument of the in-scope <c>HybridKem.Decapsulate(...)</c> call (for
/// the decap flow). If neither is found, the fix inserts a TODO
/// placeholder argument that fails closed at runtime — the developer
/// must replace it with the actual KEM ciphertext expression.
/// </remarks>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(AddAssociatedDataCodeFix)), Shared]
public sealed class AddAssociatedDataCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create(AeadWithoutKemBindingAnalyzer.DiagnosticId);

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
            var invocation = node.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
            if (invocation?.ArgumentList is null)
            {
                continue;
            }
            if (invocation.ArgumentList.Arguments.Count >= 5)
            {
                continue; // already has associatedData
            }

            var methodBody = invocation.AncestorsAndSelf()
                .FirstOrDefault(n => n is BlockSyntax { Parent: MethodDeclarationSyntax or LocalFunctionStatementSyntax });

            var aadExpression = FindLikelyAssociatedDataExpression(methodBody);

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: aadExpression is null
                        ? "Add associatedData: TODO (KEM ciphertext)"
                        : $"Add associatedData: {aadExpression}",
                    createChangedDocument: ct => AddAsync(context.Document, invocation, aadExpression, ct),
                    equivalenceKey: "PQH005:add-aad"),
                diagnostic);
        }
    }

    private static string? FindLikelyAssociatedDataExpression(SyntaxNode? methodBody)
    {
        if (methodBody is null)
        {
            return null;
        }

        // 1. Look for a local var declared from HybridKem.Encapsulate(...) → use <var>.Ciphertext.
        foreach (var decl in methodBody.DescendantNodes().OfType<VariableDeclaratorSyntax>())
        {
            if (decl.Initializer?.Value is not InvocationExpressionSyntax invocation)
            {
                continue;
            }
            if (invocation.Expression is MemberAccessExpressionSyntax member
                && member.Name.Identifier.Text == "Encapsulate"
                && (member.Expression.ToString() == "HybridKem"
                    || member.Expression.ToString().EndsWith(".HybridKem", System.StringComparison.Ordinal)))
            {
                return decl.Identifier.Text + ".Ciphertext";
            }
        }

        // 2. Look for HybridKem.Decapsulate(privateKey, ciphertext) and reuse its `ciphertext` argument.
        foreach (var invocation in methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member)
            {
                continue;
            }
            if (member.Name.Identifier.Text != "Decapsulate")
            {
                continue;
            }
            var receiver = member.Expression.ToString();
            if (receiver != "HybridKem" && !receiver.EndsWith(".HybridKem", System.StringComparison.Ordinal))
            {
                continue;
            }
            if (invocation.ArgumentList is { Arguments.Count: >= 2 } argList)
            {
                return argList.Arguments[1].Expression.ToString();
            }
        }

        return null;
    }

    private static async Task<Document> AddAsync(
        Document document,
        InvocationExpressionSyntax invocation,
        string? aadExpressionText,
        CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return document;
        }

        var argumentExpression = aadExpressionText is null
            ? SyntaxFactory.ParseExpression("default(System.ReadOnlySpan<byte>) /* PQH005: replace with KEM ciphertext */")
            : SyntaxFactory.ParseExpression(aadExpressionText);

        var aadArgument = SyntaxFactory.Argument(argumentExpression)
            .WithNameColon(SyntaxFactory.NameColon("associatedData"));

        var newArgList = invocation.ArgumentList!.AddArguments(aadArgument);
        var newInvocation = invocation.WithArgumentList(newArgList);

        var newRoot = root.ReplaceNode(invocation, newInvocation);
        return document.WithSyntaxRoot(newRoot);
    }
}
