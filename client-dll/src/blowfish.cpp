#include "blowfish.h"
#include "blowfish_tables.h"
#include <cstring>

Blowfish::Blowfish(const uint8_t* key, size_t keyLen)
{
    std::memcpy(P, BF_P_INIT, sizeof(P));
    std::memcpy(S, BF_S_INIT, sizeof(S));

    // Mistura a chave no P-array (ciclando a chave).
    size_t k = 0;
    for (int i = 0; i < 18; ++i)
    {
        uint32_t data = 0;
        for (int j = 0; j < 4; ++j)
        {
            data = (data << 8) | key[k];
            k = (k + 1) % keyLen;
        }
        P[i] ^= data;
    }

    // Gera as sub-chaves finais.
    uint32_t xl = 0, xr = 0;
    for (int i = 0; i < 18; i += 2)
    {
        EncryptBlock(xl, xr);
        P[i] = xl;
        P[i + 1] = xr;
    }
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 256; j += 2)
        {
            EncryptBlock(xl, xr);
            S[i][j] = xl;
            S[i][j + 1] = xr;
        }
    }
}

uint32_t Blowfish::F(uint32_t x) const
{
    uint32_t a = S[0][(x >> 24) & 0xFF];
    uint32_t b = S[1][(x >> 16) & 0xFF];
    uint32_t c = S[2][(x >> 8) & 0xFF];
    uint32_t d = S[3][x & 0xFF];
    return ((a + b) ^ c) + d;
}

void Blowfish::EncryptBlock(uint32_t& xl, uint32_t& xr) const
{
    for (int i = 0; i < 16; i += 2)
    {
        xl ^= P[i];
        xr ^= F(xl);
        xr ^= P[i + 1];
        xl ^= F(xr);
    }
    xl ^= P[16];
    xr ^= P[17];
    uint32_t t = xl; xl = xr; xr = t;
}

void Blowfish::DecryptBlock(uint32_t& xl, uint32_t& xr) const
{
    for (int i = 17; i > 1; i -= 2)
    {
        xl ^= P[i];
        xr ^= F(xl);
        xr ^= P[i - 1];
        xl ^= F(xr);
    }
    xl ^= P[1];
    xr ^= P[0];
    uint32_t t = xl; xl = xr; xr = t;
}

static inline uint32_t ReadLE(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void WriteLE(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

void Blowfish::L2Decrypt(uint8_t* data, size_t len) const
{
    size_t blocks = len / 8;
    for (size_t b = 0; b < blocks; ++b)
    {
        uint8_t* p = data + b * 8;
        uint32_t xl = ReadLE(p), xr = ReadLE(p + 4);
        DecryptBlock(xl, xr);
        WriteLE(p, xl);
        WriteLE(p + 4, xr);
    }
}

void Blowfish::L2Encrypt(uint8_t* data, size_t len) const
{
    size_t blocks = len / 8;
    for (size_t b = 0; b < blocks; ++b)
    {
        uint8_t* p = data + b * 8;
        uint32_t xl = ReadLE(p), xr = ReadLE(p + 4);
        EncryptBlock(xl, xr);
        WriteLE(p, xl);
        WriteLE(p + 4, xr);
    }
}
