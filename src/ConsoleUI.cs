using System;

namespace JNukeCrypt;

/// <summary>
/// Responsável por toda a apresentação no console: banner, mensagens de
/// status, avisos e erros. Isola a camada de UI da lógica de processamento.
/// </summary>
internal static class ConsoleUI
{
    public static void ShowBanner()
    {
        try
        {
            int width = Math.Min(92, Console.LargestWindowWidth);
            int height = Math.Min(24, Console.LargestWindowHeight);

            Console.SetWindowSize(width, height);
            Console.SetBufferSize(width, Math.Max(height, 120));
        }
        catch
        {
            // Redimensionamento pode falhar em terminais não interativos; ignorar.
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"      ____.__________        __            _________                       __   
     |    |\______   \__ __ |  | __ ____ \_   ___ \_______ ___.__._______/  |_ 
     |    | |    |  _/  |  \|  |/ // __ \/    \  \/\_  __ <   |  |\____ \   __\
 /\__|    | |    |   \  |  /    <\  ___/\     \____|  | \/\___  ||  |_> >  |  
 \________| |______  /____/|__|_ \\___  >\______  /|__|   / ____||   __/|__|  
                   \/           \/    \/        \/        \/     |__|         ");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("                                                                        v1.5.2.2");
        Console.ResetColor();

        Console.WriteLine("  Licensed to: JNuke          E-mail: JNuke@gmail.net");
        Console.WriteLine();
    }

    public static void ShowUsage()
    {
        Console.WriteLine("Arraste arquivos .dat, .u, .ukx ou .utx sobre o JNukeCrypt.exe.");
        Console.WriteLine();
        Console.WriteLine("O programa detecta automaticamente se deve ENCRYPTAR ou DECRYPTAR.");
        Console.WriteLine();
        Console.WriteLine("Pressione qualquer tecla para fechar...");
    }

    public static void PrintProcessing(string path)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"Processing file: {path}");
        Console.ResetColor();
    }

    public static void PrintUnsupported(string fileName)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"IGNORADO: {fileName}");
        Console.WriteLine("Extensao nao suportada. Use .dat, .u, .ukx ou .utx.");
        Console.ResetColor();
        Console.WriteLine();
    }

    public static void PrintStatus(CryptoAction action)
    {
        Console.WriteLine();

        switch (action)
        {
            case CryptoAction.Encrypt:
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" ---------------------------------");
                Console.WriteLine("|   File successfully encrypted!  |");
                Console.WriteLine(" ---------------------------------");
                break;

            case CryptoAction.Decrypt:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" ---------------------------------");
                Console.WriteLine("|  File successfully de-crypted!  |");
                Console.WriteLine(" ---------------------------------");
                break;

            default:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(" ---------------------------------");
                Console.WriteLine("|   File successfully crypted!    |");
                Console.WriteLine(" ---------------------------------");
                break;
        }

        Console.ResetColor();
        Console.WriteLine();
    }

    public static void PrintError(string file, string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"ERRO: {file}");
        Console.WriteLine(message);
        Console.ResetColor();
        Console.WriteLine();
    }
}
