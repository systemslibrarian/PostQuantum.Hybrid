using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// PQH004 — flags <c>HybridSignature.Verify(...)</c> invocations whose
/// boolean return value is discarded. Failing to check the result is
/// equivalent to <c>alg: none</c>: the caller proceeds as if verification
/// passed regardless of the actual outcome.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class IgnoredVerifyResultAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "PQH004";

    private static readonly LocalizableString Title =
        "HybridSignature.Verify result discarded";

    private static readonly LocalizableString MessageFormat =
        "The return value of HybridSignature.Verify must be checked; ignoring it is equivalent to skipping signature verification";

    private static readonly LocalizableString Description =
        "HybridSignature.Verify returns a bool. Discarding it lets the caller " +
        "treat unauthenticated input as authenticated. Capture the result and " +
        "branch on it (typically: throw a CryptographicException on false).";

    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticId,
        title: Title,
        messageFormat: MessageFormat,
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: Description,
        helpLinkUri: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/README.md");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        if (!IsHybridSignatureVerify(invocation))
        {
            return;
        }

        // The invocation is "ignored" if it is its own ExpressionStatement,
        // i.e. the bool result is thrown away.
        if (invocation.Parent is ExpressionStatementSyntax)
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, invocation.GetLocation()));
            return;
        }

        // Explicit `_ = HybridSignature.Verify(...);` is also "ignored".
        if (invocation.Parent is AssignmentExpressionSyntax assignment
            && assignment.Left is IdentifierNameSyntax id
            && id.Identifier.Text == "_")
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, invocation.GetLocation()));
            return;
        }
    }

    private static bool IsHybridSignatureVerify(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax member)
        {
            return false;
        }
        if (member.Name.Identifier.Text != "Verify")
        {
            return false;
        }
        // Cheap textual gate first.
        var receiver = member.Expression.ToString();
        return receiver == "HybridSignature"
            || receiver.EndsWith(".HybridSignature", System.StringComparison.Ordinal);
    }
}
