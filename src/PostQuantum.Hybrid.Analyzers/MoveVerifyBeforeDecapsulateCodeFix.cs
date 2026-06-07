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
/// Quick-fix for PQH003: move the statement containing the first
/// <c>HybridSignature.Verify(...)</c> call above the statement containing
/// the flagged <c>HybridKem.Decapsulate(...)</c> call so verification
/// precedes decapsulation.
/// </summary>
/// <remarks>
/// This is a conservative, textual reordering: it moves the immediately
/// enclosing statement (typically an <c>if</c>-throw guard) and leaves
/// everything else alone. If the verify result is split across multiple
/// statements (e.g. <c>var ok = ...;</c> followed by <c>if (!ok) throw;</c>),
/// the user is expected to inspect and adjust manually.
/// </remarks>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(MoveVerifyBeforeDecapsulateCodeFix)), Shared]
public sealed class MoveVerifyBeforeDecapsulateCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create(DecapsulateBeforeVerifyAnalyzer.DiagnosticId);

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
            var decapNode = root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true);
            var decapInvocation = decapNode.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
            if (decapInvocation is null)
            {
                continue;
            }

            var decapStatement = decapInvocation.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
            if (decapStatement is null || decapStatement.Parent is not BlockSyntax decapBlock)
            {
                continue;
            }

            var verifyInvocation = FindFirstHybridSignatureVerify(decapBlock.Parent ?? decapBlock);
            if (verifyInvocation is null)
            {
                continue;
            }
            var verifyStatement = verifyInvocation.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
            if (verifyStatement is null || verifyStatement.Parent is not BlockSyntax verifyBlock)
            {
                continue;
            }
            if (verifyBlock != decapBlock)
            {
                // The verify is in a different block (nested if, lambda, etc.). The
                // textual transformation is no longer safe; leave for manual fix.
                continue;
            }
            if (verifyStatement.SpanStart < decapStatement.SpanStart)
            {
                continue; // already in order
            }

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: "Move signature verification before decapsulation",
                    createChangedDocument: ct => MoveAsync(context.Document, decapBlock, verifyStatement, decapStatement, ct),
                    equivalenceKey: "PQH003:reorder"),
                diagnostic);
        }
    }

    private static InvocationExpressionSyntax? FindFirstHybridSignatureVerify(SyntaxNode scope)
    {
        foreach (var invocation in scope.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member)
            {
                continue;
            }
            if (member.Name.Identifier.Text != "Verify")
            {
                continue;
            }
            var receiver = member.Expression.ToString();
            if (receiver == "HybridSignature"
                || receiver.EndsWith(".HybridSignature", System.StringComparison.Ordinal))
            {
                return invocation;
            }
        }
        return null;
    }

    private static async Task<Document> MoveAsync(
        Document document,
        BlockSyntax block,
        StatementSyntax verifyStatement,
        StatementSyntax decapStatement,
        CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return document;
        }

        var statements = block.Statements;
        var newStatements = statements
            .Remove(verifyStatement)
            .Insert(statements.IndexOf(decapStatement), verifyStatement.WithoutTrailingTrivia().WithTrailingTrivia(SyntaxFactory.CarriageReturnLineFeed));

        var newBlock = block.WithStatements(newStatements);
        var newRoot = root.ReplaceNode(block, newBlock);
        return document.WithSyntaxRoot(newRoot);
    }
}
