// Motor Blowfish + camada L2 (blowfish-compat, ECB, blocos little-endian).
// Porte fiel da implementacao C# validada (7/7 vetores oficiais).
#pragma once
#include <cstdint>
#include <cstddef>

class Blowfish
{
public:
    // key/keyLen: bytes da chave (2..56 bytes tipicamente).
    Blowfish(const uint8_t* key, size_t keyLen);

    // Cifra/decifra um bloco de 64 bits (dois meio-blocos).
    void EncryptBlock(uint32_t& xl, uint32_t& xr) const;
    void DecryptBlock(uint32_t& xl, uint32_t& xr) const;

    // Aplica sobre um buffer no formato L2: ECB, blocos de 8 bytes lidos em
    // LITTLE-ENDIAN. A cauda (< 8 bytes) fica inalterada.
    void L2Decrypt(uint8_t* data, size_t len) const;
    void L2Encrypt(uint8_t* data, size_t len) const;

private:
    uint32_t F(uint32_t x) const;

    uint32_t P[18];
    uint32_t S[4][256];
};
