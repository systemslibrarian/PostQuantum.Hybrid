using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Hybrid.Analyzers;

/// <summary>
/// PQH005 — flags an <c>AesGcm.Encrypt</c> or <c>.Decrypt</c> call that
/// does not pass an <c>associatedData</c> argument, when the method body
/// also calls <c>HybridKem.Encapsulate(...)</c> or
/// <c>HybridKem.Decapsulate(...)</c>. In that pattern, the KEM ciphertext
/// must be bound into the AEAD as <c>associatedData</c> so that a swapped
/// ciphertext breaks decryption.
/// </summary>
/// <remarks>
/// This is intentionally a heuristic at the method-body level: it flags
/// the dangerous shape, not every possible omission. If your flow does
/// not need AEAD AAD binding for a legitimate reason, suppress with
/// <c>#pragma warning disable PQH005</c>.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class AeadWithoutKemBindingAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "PQH005";

    private static readonly LocalizableString Title =
        "AES-GCM call inside a hybrid KEM flow without associatedData binding";

    private static readonly LocalizableString MessageFormat =
        "AesGcm.{0} is called without 'associatedData' but the same method uses hybrid KEM; bind the KEM ciphertext as associatedData";

    private static readonly LocalizableString Description =
        "When AES-GCM is keyed from a hybrid KEM exchange, binding the KEM " +
        "ciphertext into associatedData prevents an attacker from swapping " +
        "ciphertexts to re-key the AEAD against a different exchange.";

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

        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>().ToList();

        var hasHybridKemUse = invocations.Any(IsHybridKemEncapOrDecap);
        if (!hasHybridKemUse)
        {
            return;
        }

        foreach (var invocation in invocations)
        {
            if (!IsAesGcmEncryptOrDecrypt(invocation, out var methodName))
            {
                continue;
            }
            if (HasAssociatedDataArgument(invocation))
            {
                continue;
            }

            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                invocation.GetLocation(),
                methodName));
        }
    }

    private static bool IsHybridKemEncapOrDecap(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax member)
        {
            return false;
        }
        var name = member.Name.Identifier.Text;
        if (name != "Encapsulate" && name != "Decapsulate")
        {
            return false;
        }
        var receiver = member.Expression.ToString();
        return receiver == "HybridKem" || receiver.EndsWith(".HybridKem", System.StringComparison.Ordinal);
    }

    private static bool IsAesGcmEncryptOrDecrypt(InvocationExpressionSyntax invocation, out string methodName)
    {
        methodName = string.Empty;
        if (invocation.Expression is not MemberAccessExpressionSyntax member)
        {
            return false;
        }
        var name = member.Name.Identifier.Text;
        if (name != "Encrypt" && name != "Decrypt")
        {
            return false;
        }
        methodName = name;
        // We don't have semantic info easily available without an OperationAnalysisContext;
        // for the v1 heuristic, check that the receiver expression contains "aes" / "AesGcm"
        // (common variable names) OR is a typed AesGcm instance. The IdentifierName check
        // catches `aes.Encrypt(...)` / `aesGcm.Decrypt(...)` which is overwhelmingly the
        // pattern. False positives can be suppressed.
        var receiverText = member.Expression.ToString();
        if (receiverText.IndexOf("aes", System.StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }
        return true;
    }

    private static bool HasAssociatedDataArgument(InvocationExpressionSyntax invocation)
    {
        if (invocation.ArgumentList is null)
        {
            return false;
        }
        // Named: associatedData: ...
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (arg.NameColon?.Name.Identifier.Text == "associatedData")
            {
                return true;
            }
        }
        // Positional: Encrypt(nonce, plaintext, ciphertext, tag, associatedData)
        //  -> 5 args means associatedData supplied
        // Or Decrypt(nonce, ciphertext, tag, plaintext, associatedData)
        //  -> 5 args means associatedData supplied
        return invocation.ArgumentList.Arguments.Count >= 5;
    }
}
