using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// PQH003 — flags any method body that calls
/// <c>HybridKem.Decapsulate(...)</c> earlier than
/// <c>HybridSignature.Verify(...)</c>. The standard sign-then-encrypt
/// flow must verify the sender's signature BEFORE decapsulating, so that
/// the recipient never derives a shared secret from unauthenticated input.
/// </summary>
/// <remarks>
/// This is a textual order check within a single method body. If your
/// flow legitimately decapsulates first (e.g. anonymous encrypted
/// envelope), suppress with <c>#pragma warning disable PQH003</c>.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class DecapsulateBeforeVerifyAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "PQH003";

    private static readonly LocalizableString Title =
        "HybridKem.Decapsulate called before HybridSignature.Verify";

    private static readonly LocalizableString MessageFormat =
        "Decapsulating before verifying derives a shared secret from unauthenticated input; call HybridSignature.Verify first and abort on failure";

    private static readonly LocalizableString Description =
        "In sign-then-encrypt flows, verification must precede decapsulation. " +
        "Acting on unauthenticated material widens the attack surface and " +
        "can leak key-related side channels.";

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
        context.RegisterSyntaxNodeAction(AnalyzeMethodBody,
            SyntaxKind.MethodDeclaration,
            SyntaxKind.LocalFunctionStatement);
    }

    private static void AnalyzeMethodBody(SyntaxNodeAnalysisContext context)
    {
        var body = context.Node switch
        {
            MethodDeclarationSyntax m => (SyntaxNode?)m.Body ?? m.ExpressionBody,
            LocalFunctionStatementSyntax lf => (SyntaxNode?)lf.Body ?? lf.ExpressionBody,
            _ => null,
        };
        if (body is null)
        {
            return;
        }

        InvocationExpressionSyntax? firstVerify = null;
        InvocationExpressionSyntax? firstDecap = null;

        foreach (var invocation in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member)
            {
                continue;
            }

            var name = member.Name.Identifier.Text;
            var receiver = member.Expression.ToString();
            var receiverEndsWith = (string suffix) =>
                receiver == suffix || receiver.EndsWith("." + suffix, System.StringComparison.Ordinal);

            if (name == "Verify" && receiverEndsWith("HybridSignature") && firstVerify is null)
            {
                firstVerify = invocation;
            }
            else if (name == "Decapsulate" && receiverEndsWith("HybridKem") && firstDecap is null)
            {
                firstDecap = invocation;
            }

            if (firstVerify is not null && firstDecap is not null)
            {
                break;
            }
        }

        if (firstDecap is null)
        {
            return; // no decapsulation in this method, nothing to flag
        }
        if (firstVerify is null)
        {
            return; // no signature check anywhere in this method — different concern
        }

        if (firstDecap.SpanStart < firstVerify.SpanStart)
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, firstDecap.GetLocation()));
        }
    }
}
