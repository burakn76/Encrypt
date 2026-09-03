using System;
using System.IO;
using System.Linq;
using JNukeCrypt.Blowfish;

namespace JNukeCrypt;

/// <summary>Ação detectada/aplicada a um arquivo.</summary>
internal enum CryptoAction
{
    Encrypt,
    Decrypt,
}

/// <summary>
/// Cuida da leitura, transformação e gravação atômica dos arquivos, além de
/// decidir se o arquivo deve ser encryptado ou decryptado.
///
/// Esquema: Blowfish (formato Lineage 2 família 41x). A detecção é feita pela
/// presença do header <c>Lineage2Ver413</c>:
///   - arquivo COM header  -> já está encryptado -> DECRYPT
///   - arquivo SEM header   -> arquivo cru        -> ENCRYPT
/// </summary>
internal static class FileProcessor
{
    public static readonly string[] SupportedExtensions =
    {
        ".dat", ".u", ".ukx", ".utx",
    };

    // Motor Blowfish configurado com a chave própria do servidor.
    private static readonly L2FileFormatBlowfish Format =
        new(L2ServerKey.KeyBytes);

    public static bool IsSupported(string path)
    {
        string ext = Path.GetExtension(path);
        return SupportedExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Processa um arquivo: detecta a operação, transforma o conteúdo e grava
    /// no local. Retorna a ação aplicada.
    /// </summary>
    public static CryptoAction Process(string path)
    {
        byte[] input = File.ReadAllBytes(path);

        CryptoAction action;
        byte[] output;

        if (L2FileFormatBlowfish.HasHeader(input))
        {
            // Já tem header 413 -> está encryptado -> decrypta.
            output = Format.Decrypt(input);
            action = CryptoAction.Decrypt;
        }
        else
        {
            // Arquivo cru -> adiciona header e cifra o corpo.
            output = Format.Encrypt(input);
            action = CryptoAction.Encrypt;
        }

        WriteAtomic(path, output);
        return action;
    }

    /// <summary>
    /// Grava em arquivo temporário e move sobre o destino, evitando arquivos
    /// corrompidos caso a escrita seja interrompida.
    /// </summary>
    private static void WriteAtomic(string path, byte[] data)
    {
        string dir = Path.GetDirectoryName(path) ?? ".";
        string temp = Path.Combine(
            dir,
            "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");

        try
        {
            File.WriteAllBytes(temp, data);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
                File.Delete(temp);
        }
    }
}
