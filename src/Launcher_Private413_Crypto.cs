using System;
using JNukeCrypt.Blowfish;

namespace JNukeCrypt;

/// <summary>
/// Fachada de compatibilidade para o launcher/cliente. Aplica o mesmo esquema
/// Blowfish (formato 41x) usado pelo encryptor. Use a MESMA chave dos dois
/// lados (<see cref="L2ServerKey"/>).
///
/// - <see cref="DecryptFile"/>: recebe um arquivo com header 413 e devolve o
///   corpo decifrado (o que o cliente precisa para ler o conteúdo original).
/// - <see cref="EncryptFile"/>: recebe conteúdo cru e devolve o arquivo com
///   header + corpo cifrado.
/// </summary>
internal static class JNukePrivate413Crypto
{
    private static readonly L2FileFormatBlowfish Format = new(L2ServerKey.KeyBytes);

    public static byte[] EncryptFile(ReadOnlySpan<byte> rawBody) => Format.Encrypt(rawBody);

    public static byte[] DecryptFile(ReadOnlySpan<byte> file) => Format.Decrypt(file);
}
