using System;
using System.Text;

namespace JNukeCrypt;

/// <summary>
/// Ponto de entrada. Recebe os arquivos arrastados sobre o executável,
/// delega a detecção/transformação para <see cref="FileProcessor"/> e usa
/// <see cref="ConsoleUI"/> para toda a apresentação.
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        Console.Title = "JNukeCrypt - Original Keys";
        Console.OutputEncoding = Encoding.UTF8;

        ConsoleUI.ShowBanner();

        if (args.Length == 0)
        {
            ConsoleUI.ShowUsage();
            Console.ReadKey(true);
            return 0;
        }

        int errors = 0;

        foreach (string rawPath in args)
        {
            string path = rawPath.Trim().Trim('"');

            if (!System.IO.File.Exists(path))
            {
                ConsoleUI.PrintError(System.IO.Path.GetFileName(path), "Arquivo nao encontrado.");
                errors++;
                continue;
            }

            if (!FileProcessor.IsSupported(path))
            {
                ConsoleUI.PrintUnsupported(System.IO.Path.GetFileName(path));
                continue;
            }

            try
            {
                ConsoleUI.PrintProcessing(path);
                CryptoAction action = FileProcessor.Process(path);
                ConsoleUI.PrintStatus(action);
            }
            catch (Exception ex)
            {
                ConsoleUI.PrintError(System.IO.Path.GetFileName(path), ex.Message);
                errors++;
            }
        }

        Console.WriteLine();
        Console.WriteLine("Pressione qualquer tecla para continuar. . .");
        Console.ReadKey(true);

        return errors == 0 ? 0 : 10;
    }
}
