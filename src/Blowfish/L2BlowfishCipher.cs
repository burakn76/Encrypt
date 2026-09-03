using System;

namespace JNukeCrypt.Blowfish;

/// <summary>
/// Camada que aplica o Blowfish sobre buffers no formato usado pelo cliente
/// Lineage 2 (família 41x): modo ECB, blocos de 8 bytes, com a variante
/// "blowfish-compat" — os dois meio-blocos são lidos/gravados em
/// LITTLE-ENDIAN (e não no big-endian padrão do Blowfish).
///
/// Bytes que sobram (arquivo não múltiplo de 8) são deixados como estão,
/// exatamente como o cliente L2 faz: apenas os blocos completos de 8 bytes
/// são cifrados.
/// </summary>
internal sealed class L2BlowfishCipher
{
    private const int BlockBytes = 8;
    private readonly BlowfishEngine _engine;

    public L2BlowfishCipher(byte[] key) => _engine = new BlowfishEngine(key);

    public byte[] Encrypt(ReadOnlySpan<byte> data)
        => Process(data, encrypt: true);

    public byte[] Decrypt(ReadOnlySpan<byte> data)
        => Process(data, encrypt: false);

    private byte[] Process(ReadOnlySpan<byte> data, bool encrypt)
    {
        byte[] output = data.ToArray();
        int fullBlocks = output.Length / BlockBytes;

        for (int b = 0; b < fullBlocks; b++)
        {
            int off = b * BlockBytes;

            // Leitura little-endian (blowfish-compat do L2).
            uint xl = ReadLE(output, off);
            uint xr = ReadLE(output, off + 4);

            if (encrypt)
                _engine.EncryptBlock(ref xl, ref xr);
            else
                _engine.DecryptBlock(ref xl, ref xr);

            WriteLE(output, off, xl);
            WriteLE(output, off + 4, xr);
        }

        // A cauda (< 8 bytes) permanece inalterada, como no cliente.
        return output;
    }

    private static uint ReadLE(byte[] buf, int off)
        => (uint)(buf[off]
                | (buf[off + 1] << 8)
                | (buf[off + 2] << 16)
                | (buf[off + 3] << 24));

    private static void WriteLE(byte[] buf, int off, uint value)
    {
        buf[off] = (byte)(value & 0xFF);
        buf[off + 1] = (byte)((value >> 8) & 0xFF);
        buf[off + 2] = (byte)((value >> 16) & 0xFF);
        buf[off + 3] = (byte)((value >> 24) & 0xFF);
    }
}
