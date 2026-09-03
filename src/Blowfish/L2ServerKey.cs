using System;
using System.Text;

namespace JNukeCrypt.Blowfish;

/// <summary>
/// Chave Blowfish exclusiva do SEU servidor. Este é o único ponto a alterar
/// para gerar um encrypt próprio: troque <see cref="KeyText"/> por uma frase
/// secreta sua (ou use <see cref="FromPassphrase"/>). A MESMA chave precisa
/// ser configurada no lado que decripta no cliente.
///
/// IMPORTANTE: mantenha esta chave em segredo. Quem tiver a chave consegue
/// decriptar seus arquivos.
/// </summary>
internal static class L2ServerKey
{
    /// <summary>
    /// Frase-chave do servidor. TROQUE por um valor secreto e único seu.
    /// (Placeholder de exemplo — não use este valor em produção.)
    /// </summary>
    public const string KeyText = "TROQUE_ESTA_CHAVE_DO_SEU_SERVIDOR_L2";

    /// <summary>Bytes da chave usados pelo Blowfish (UTF-8 da frase).</summary>
    public static byte[] KeyBytes => Encoding.UTF8.GetBytes(KeyText);

    /// <summary>Constrói bytes de chave a partir de uma frase arbitrária.</summary>
    public static byte[] FromPassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase vazia.", nameof(passphrase));
        return Encoding.UTF8.GetBytes(passphrase);
    }
}
