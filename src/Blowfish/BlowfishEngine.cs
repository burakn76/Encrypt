using System;

namespace JNukeCrypt.Blowfish;

/// <summary>
/// Implementação pura do cifrador de bloco Blowfish (Bruce Schneier, 1993).
/// Bloco de 64 bits (8 bytes), chave de 32 a 448 bits. As tabelas P e S são
/// os valores canônicos derivados dos dígitos de pi.
///
/// Esta classe trabalha com os dois meio-blocos já como uint (xL, xR). A
/// conversão de/para bytes (e a endianness específica do L2) fica na camada
/// superior (<see cref="L2BlowfishCipher"/>), mantendo este motor genérico.
/// </summary>
internal sealed class BlowfishEngine
{
    private const int Rounds = 16;

    private readonly uint[] _p = new uint[Rounds + 2];
    private readonly uint[,] _s = new uint[4, 256];

    public BlowfishEngine(byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Chave Blowfish nao pode ser vazia.", nameof(key));

        Array.Copy(BlowfishTables.P, _p, BlowfishTables.P.Length);
        var sInit = BlowfishTables.S;
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 256; j++)
                _s[i, j] = sInit[i, j];

        // Mistura a chave no P-array (ciclando a chave conforme necessário).
        int keyIndex = 0;
        for (int i = 0; i < Rounds + 2; i++)
        {
            uint data = 0;
            for (int k = 0; k < 4; k++)
            {
                data = (data << 8) | key[keyIndex];
                keyIndex = (keyIndex + 1) % key.Length;
            }
            _p[i] ^= data;
        }

        // Sub-chaves finais: cifra o bloco zero repetidamente e substitui P e S.
        uint xl = 0, xr = 0;
        for (int i = 0; i < Rounds + 2; i += 2)
        {
            EncryptBlock(ref xl, ref xr);
            _p[i] = xl;
            _p[i + 1] = xr;
        }
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 256; j += 2)
            {
                EncryptBlock(ref xl, ref xr);
                _s[i, j] = xl;
                _s[i, j + 1] = xr;
            }
        }
    }

    private uint F(uint x)
    {
        uint a = _s[0, (x >> 24) & 0xFF];
        uint b = _s[1, (x >> 16) & 0xFF];
        uint c = _s[2, (x >> 8) & 0xFF];
        uint d = _s[3, x & 0xFF];
        return ((a + b) ^ c) + d;
    }

    public void EncryptBlock(ref uint xl, ref uint xr)
    {
        for (int i = 0; i < Rounds; i += 2)
        {
            xl ^= _p[i];
            xr ^= F(xl);
            xr ^= _p[i + 1];
            xl ^= F(xr);
        }
        xl ^= _p[Rounds];
        xr ^= _p[Rounds + 1];

        (xl, xr) = (xr, xl);
    }

    public void DecryptBlock(ref uint xl, ref uint xr)
    {
        for (int i = Rounds + 1; i > 1; i -= 2)
        {
            xl ^= _p[i];
            xr ^= F(xl);
            xr ^= _p[i - 1];
            xl ^= F(xr);
        }
        xl ^= _p[1];
        xr ^= _p[0];

        (xl, xr) = (xr, xl);
    }
}
