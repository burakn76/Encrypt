using System;
using System.IO;
using System.Linq;

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
/// </summary>
internal static class FileProcessor
{
    public static readonly string[] SupportedExtensions =
    {
        ".dat", ".u", ".ukx", ".utx",
    };

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

        bool currentlyUnlocked = CryptoEngine.IsUnlocked(input);
        byte[] output = CryptoEngine.Transform(input);
        bool outputUnlocked = CryptoEngine.IsUnlocked(output);

        CryptoAction action;

        if (currentlyUnlocked)
        {
            // Arquivo original (Lineage2Ver413) -> vamos bloquear.
            action = CryptoAction.Encrypt;
        }
        else if (outputUnlocked)
        {
            // Ao transformar, restaurou o header original -> estava encryptado.
            action = CryptoAction.Decrypt;
        }
        else
        {
            throw new InvalidDataException(
                "Arquivo nao reconhecido como Lineage2Ver413 original ou 413 encryptado.");
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
