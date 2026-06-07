using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// PQH002 — flags <c>.SharedSecret</c> property access on
/// <c>HybridKemEncapsulationResult</c> being passed directly into a
/// symmetric-crypto constructor or being used as the entire argument to
/// an AEAD/MAC primitive, instead of being fed through a KDF.
/// </summary>
/// <remarks>
/// This is a heuristic: it pattern-matches the common misuse where a
/// caller writes <c>new AesGcm(enc.SharedSecret, ...)</c> or
/// <c>new HMACSHA256(enc.SharedSecret)</c>. False positives are possible
/// if the caller is in fact using the secret as raw seed material with
/// awareness of the implications; suppress with <c>#pragma warning
/// disable PQH002</c> when justified.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SharedSecretWithoutHkdfAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "PQH002";

    private static readonly LocalizableString Title =
        "Hybrid KEM SharedSecret used as a key without HKDF";

    private static readonly LocalizableString MessageFormat =
        "'{0}' is being passed directly to a symmetric primitive constructor; feed it through HKDF.Expand with a purpose-specific 'info' first";

    private static readonly LocalizableString Description =
        "A hybrid KEM SharedSecret is uniform 32 bytes — coincidentally what " +
        "AES-256 needs — but using it directly loses domain separation. Feed " +
        "it through HKDF.Expand with a purpose-specific 'info' parameter and " +
        "use the resulting key.";

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

    // Receiver types whose constructor accepting a key directly we want to flag.
    private static readonly ImmutableHashSet<string> FlaggedConstructorTypes =
        ImmutableHashSet.Create(
            "System.Security.Cryptography.AesGcm",
            "System.Security.Cryptography.AesCcm",
            "System.Security.Cryptography.ChaCha20Poly1305",
            "System.Security.Cryptography.HMACSHA256",
            "System.Security.Cryptography.HMACSHA384",
            "System.Security.Cryptography.HMACSHA512",
            "System.Security.Cryptography.HMACSHA1");

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var creation = (ObjectCreationExpressionSyntax)context.Node;
        var typeInfo = context.SemanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString();
        if (typeName is null || !FlaggedConstructorTypes.Contains(typeName))
        {
            return;
        }

        if (creation.ArgumentList is null || creation.ArgumentList.Arguments.Count == 0)
        {
            return;
        }
        var firstArg = creation.ArgumentList.Arguments[0].Expression;

        if (!IsSharedSecretAccess(firstArg, context))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            Rule,
            firstArg.GetLocation(),
            firstArg.ToString()));
    }

    private static bool IsSharedSecretAccess(ExpressionSyntax expr, SyntaxNodeAnalysisContext context)
    {
        // Walk inside common transparent wrappers like ".SharedSecret.AsSpan(...)".
        if (expr is InvocationExpressionSyntax invocation
            && invocation.Expression is MemberAccessExpressionSyntax invokedMember
            && (invokedMember.Name.Identifier.Text == "AsSpan"
                || invokedMember.Name.Identifier.Text == "ToArray"
                || invokedMember.Name.Identifier.Text == "AsMemory"))
        {
            return IsSharedSecretAccess(invokedMember.Expression, context);
        }

        if (expr is not MemberAccessExpressionSyntax member)
        {
            return false;
        }
        if (member.Name.Identifier.Text != "SharedSecret")
        {
            return false;
        }

        var receiverType = context.SemanticModel.GetTypeInfo(member.Expression).Type;
        return receiverType?.ToDisplayString() == "PostQuantum.Hybrid.HybridKemEncapsulationResult";
    }
}
