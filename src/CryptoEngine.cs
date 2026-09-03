using System;
using System.Text;

namespace JNukeCrypt;

/// <summary>
/// Motor de criptografia XOR por blocos de 256 bytes, compatível com o
/// esquema Lineage2Ver413. A transformação é involutiva (XOR): aplicar duas
/// vezes retorna ao conteúdo original, portanto o mesmo método serve tanto
/// para encryptar quanto para decryptar.
/// </summary>
internal static class CryptoEngine
{
    /// <summary>Tamanho de cada bloco / tabela de chave, em bytes.</summary>
    public const int BlockSize = 256;

    /// <summary>Assinatura do arquivo original/desbloqueado (UTF-16LE).</summary>
    public static readonly byte[] Ver413Header =
        Encoding.Unicode.GetBytes("Lineage2Ver413");

    /// <summary>
    /// Aplica a máscara XOR por blocos. Como é XOR, é reversível: o mesmo
    /// método encrypta e decrypta.
    /// </summary>
    public static byte[] Transform(ReadOnlySpan<byte> data)
    {
        byte[] output = new byte[data.Length];

        for (int pos = 0; pos < data.Length; pos++)
        {
            int block = pos / BlockSize;
            int offset = pos % BlockSize;
            output[pos] = (byte)(data[pos] ^ MaskFor(block, offset));
        }

        return output;
    }

    /// <summary>
    /// Retorna o byte de máscara para uma dada posição de bloco/offset.
    /// Bloco 0 usa <see cref="CryptoKeys.SpecialFirst"/>; os demais alternam
    /// entre K1, K2 e K3.
    /// </summary>
    private static byte MaskFor(int block, int offset)
    {
        if (block == 0)
            return CryptoKeys.SpecialFirst[offset];

        return ((block - 1) % 3) switch
        {
            0 => CryptoKeys.K1[offset],
            1 => CryptoKeys.K2[offset],
            _ => CryptoKeys.K3[offset],
        };
    }

    /// <summary>Indica se o buffer começa com a assinatura informada.</summary>
    public static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (data.Length < signature.Length)
            return false;

        return data[..signature.Length].SequenceEqual(signature);
    }

    /// <summary>Conveniência: o buffer é um arquivo Ver413 desbloqueado?</summary>
    public static bool IsUnlocked(ReadOnlySpan<byte> data) => StartsWith(data, Ver413Header);
}
