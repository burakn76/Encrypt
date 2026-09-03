using System;
using System.Text;

namespace JNukeCrypt.Blowfish;

/// <summary>
/// Formato de arquivo do cliente Lineage 2 (família 41x) usando Blowfish.
///
/// Layout:
///   [ header UTF-16LE: "Lineage2Ver" + versao (3 digitos) ]  (texto claro)
///   [ corpo cifrado com Blowfish-ECB (blowfish-compat)     ]
///
/// O header fica em texto claro para o cliente identificar a versão; apenas o
/// corpo (após o header) é cifrado. Esta classe monta/desmonta esse layout e
/// decide se deve encryptar ou decryptar.
/// </summary>
internal sealed class L2FileFormatBlowfish
{
    // Versão da família 41x que dispara o modo Blowfish no cliente Interlude.
    private const string HeaderPrefix = "Lineage2Ver";
    private const string Version = "413";

    private static readonly byte[] HeaderBytes =
        Encoding.Unicode.GetBytes(HeaderPrefix + Version); // UTF-16LE

    private readonly L2BlowfishCipher _cipher;

    public L2FileFormatBlowfish(byte[] key) => _cipher = new L2BlowfishCipher(key);

    /// <summary>Tamanho do header em bytes (UTF-16LE).</summary>
    public static int HeaderLength => HeaderBytes.Length;

    /// <summary>O arquivo já começa com o header Lineage2Ver413?</summary>
    public static bool HasHeader(ReadOnlySpan<byte> data)
        => data.Length >= HeaderBytes.Length
           && data[..HeaderBytes.Length].SequenceEqual(HeaderBytes);

    /// <summary>
    /// Encrypta: escreve o header em claro e cifra o corpo inteiro com Blowfish.
    /// Espera receber o conteúdo bruto do arquivo (sem header ainda), ou um
    /// arquivo que ainda NÃO tenha o header 413.
    /// </summary>
    public byte[] Encrypt(ReadOnlySpan<byte> rawBody)
    {
        byte[] encryptedBody = _cipher.Encrypt(rawBody);
        byte[] result = new byte[HeaderBytes.Length + encryptedBody.Length];
        HeaderBytes.CopyTo(result, 0);
        encryptedBody.CopyTo(result, HeaderBytes.Length);
        return result;
    }

    /// <summary>
    /// Decrypta: remove o header e decifra o corpo. Requer que o arquivo
    /// comece com o header 413.
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> file)
    {
        if (!HasHeader(file))
            throw new InvalidOperationException("Arquivo sem header Lineage2Ver413.");

        ReadOnlySpan<byte> body = file[HeaderBytes.Length..];
        return _cipher.Decrypt(body);
    }
}
