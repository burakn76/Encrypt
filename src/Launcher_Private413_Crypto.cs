using System;

namespace JNukeCrypt;

/// <summary>
/// Fachada de compatibilidade para o launcher/cliente. Mantém a assinatura
/// pública <c>Transform</c> usada anteriormente, mas delega para o
/// <see cref="CryptoEngine"/> — assim as chaves ficam num único lugar
/// (<see cref="CryptoKeys"/>) e os dois lados nunca divergem.
/// </summary>
internal static class JNukePrivate413Crypto
{
    public static byte[] Transform(ReadOnlySpan<byte> data) => CryptoEngine.Transform(data);
}
