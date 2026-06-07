using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// PQH001 — flags local variables of disposable PostQuantum.Hybrid types
/// that are not declared with <c>using</c>. This is a heuristic, not a
/// flow analysis: it catches the common "forgot using" case at zero
/// runtime cost. Genuine exceptions (e.g. transferring the key into
/// long-lived storage) can be silenced with <c>#pragma warning disable PQH001</c>.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HybridDisposeAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "PQH001";

    private static readonly LocalizableString Title =
        "PostQuantum.Hybrid disposable not declared with `using`";

    private static readonly LocalizableString MessageFormat =
        "'{0}' holds sensitive key material; declare with `using` so its buffers are zeroed on dispose";

    private static readonly LocalizableString Description =
        "Hybrid private-key and encapsulation-result types zero their buffers on Dispose. " +
        "Use a `using` declaration / statement to ensure they are disposed deterministically.";

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

    private static readonly ImmutableHashSet<string> DisposableTypeNames =
        ImmutableHashSet.Create(
            "PostQuantum.Hybrid.HybridKemKeyPair",
            "PostQuantum.Hybrid.HybridKemPrivateKey",
            "PostQuantum.Hybrid.HybridSignatureKeyPair",
            "PostQuantum.Hybrid.HybridSignaturePrivateKey",
            "PostQuantum.Hybrid.HybridKemEncapsulationResult");

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration, SyntaxKind.LocalDeclarationStatement);
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        var local = (LocalDeclarationStatementSyntax)context.Node;
        if (local.UsingKeyword.IsKind(SyntaxKind.UsingKeyword))
        {
            return; // `using var foo = ...;`
        }
        if (local.Parent is UsingStatementSyntax)
        {
            return; // `using (var foo = ...) { ... }`
        }

        var typeInfo = context.SemanticModel.GetTypeInfo(local.Declaration.Type);
        var type = typeInfo.Type;
        if (type is null)
        {
            return;
        }

        var fullName = type.ToDisplayString();
        if (!DisposableTypeNames.Contains(fullName))
        {
            return;
        }

        // Skip if any variable in this declaration is initialized to null or
        // to an existing disposable (e.g. passed-in argument); only flag
        // creation expressions (`new X(...)`, `Hybrid*.GenerateKeyPair()`,
        // or any factory returning the type).
        foreach (var variable in local.Declaration.Variables)
        {
            var init = variable.Initializer?.Value;
            if (init is null)
            {
                continue;
            }
            if (!IsLikelyOwnedAllocation(init))
            {
                continue;
            }

            var diagnostic = Diagnostic.Create(
                Rule,
                variable.Identifier.GetLocation(),
                variable.Identifier.Text);
            context.ReportDiagnostic(diagnostic);
        }
    }

    private static bool IsLikelyOwnedAllocation(ExpressionSyntax expr)
    {
        // Heuristic: treat constructor calls or static factory methods on
        // the PostQuantum.Hybrid types as "the caller now owns this".
        return expr is ObjectCreationExpressionSyntax
            || expr is ImplicitObjectCreationExpressionSyntax
            || (expr is InvocationExpressionSyntax inv && IsHybridFactoryInvocation(inv));
    }

    private static bool IsHybridFactoryInvocation(InvocationExpressionSyntax invocation)
    {
        var name = invocation.Expression switch
        {
            MemberAccessExpressionSyntax m => m.Name.Identifier.Text,
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => string.Empty,
        };

        // Cheap pattern match; deliberately conservative.
        return name == "GenerateKeyPair"
            || name == "Encapsulate"
            || name == "Import"
            || name == "ImportPem";
    }
}
