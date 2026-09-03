using System;
using System.IO;
using System.Linq;
using System.Text;

internal static class Program
{
    private static readonly string[] SupportedExtensions =
    {
        ".dat", ".u", ".ukx", ".utx"
    };

    // Chaves originais que você enviou (Compatível com cliente padrão)
    private static readonly byte[] SpecialFirst = Convert.FromHexString("B3ED93CE6D00DFA9545AFBDC58D4E6E14F5A158A5CD7E0C9412DCEDD2DB0D3202D2BB8556CEF869FB0F5AF7614864525F2E821839AAAD99C490359336BA5BC73240D3EC043BC4F7976608025DDA0C330DDFBE8651CBFB6CF8025DF2644F6B515E298D1938A5AC9AC593349C35BB5AC6314DD6EB073ECBFA90630B0750D90F3C0CDCBD8750C8FA6BF90D5CF1634E6A50592C801A37A8AF97C6963B9138B45DC53042D1EA0639CAF991600A0053D80E3D0FD9B08853C5FD6EF6005FFC664D6957582F831B36ABAE98C7913A9237B55CC43F4FD4E9013CC9FC926D0D0556DF013E0EDEBF8952CAFC6DF7035EF3654C68565B22861C35AEA195C09439973AB65FCB3");
    private static readonly byte[] K1 = Convert.FromHexString("E4CD7E8003FC8FB93620C0651DE003F09DBB28A5DC7FF60F40651FE68436F555A2D811D34A9A096C197389039B75ECA3D49DAE70332CFFE9C6F0F0B54DD033808D8B18B5CC4FE6FF50150FD67426E545520841E33ACA393C29A3F953CB051C93C4ED5E6023DCEFD9D6C0E0457DC02390BD5B48C5FC1F162F20453F86A416D5B5423871F32AFA294C3953E963BB150C83B4BD8E50D30CDF09E6901095AD3053A0ADAB38D5EC6F061F30752FF69406C5A57268A1031A2A591CC983D9B3EB253CF3A48DBE40C33CCFF9F6E000A55D2043B05D7B68E59C3F364F00A55FA6C4763595621851130ADA492CD9B3C943DB352CE3945DEE30F36C3F2986B030F58D107340");
    private static readonly byte[] K2 = Convert.FromHexString("4D4B58F58C0F263F10554F96B466258512488123FA0A79FCE9E339930BC55CD384AD9E20E31C2F1996802085BD0063507D1B8805BCDF566FE0857F46E45615F50278B133EA3A690CF99329A3FBD54CC3747DCE10934C1F49A65050D5ED7093606D6B7815AC2F465FF0B56FB6D44605E532A8E143DA6A99DC89C319F32BE57C33644DFE00837C0F39B6A040E59D6083701D3BA8255CFF768FC0E59F6604B675D522589153CA1A89EC99F309831BF56C23541D2EF0B3AC7F6946707035CD50B3000D0B98354CCF667FD0958F56F4A665C5D288C163BA4AB9BCA92379D34B859C13446DDEE0A35C6F59564060C5FD40A3103DDBC8457C9F96AFA0C5BF0624965535");
    private static readonly byte[] K3 = Convert.FromHexString("C2B8F173AA7AA9CCB9D369E33B958C03343D0ED0538C5F89661090152DB0D3202D2BB8556CEF869FB0F5AF7614864525F2E821839AAAD99C490359336BA5BC73240D3EC043BC4F7976608025DDA0C330DDFBE8651CBFB6CF8025DF2644F6B515E298D1938A5AC9AC593349C35BB5AC6314DD6EB073ECBFA90630B0750D90F3C0CDCBD8750C8FA6BF90D5CF1634E6A50592C801A37A8AF97C6963B9138B45DC53042D1EA0639CAF991600A0053D80E3D0FD9B08853C5FD6EF6005FFC664D6957582F831B36ABAE98C7913A9237B55CC43F4FD4E9013CC9FC926D0D0556DF013E0EDEBF8952CAFC6DF7035EF3654C68565B22861C35AEA195C09439973AB65FCB3");

    // Arquivo original/decryptado da 413 começa com Lineage2Ver413 em UTF-16LE.
    private static readonly byte[] Ver413Header =
        Encoding.Unicode.GetBytes("Lineage2Ver413");

    [STAThread]
    private static int Main(string[] args)
    {
        Console.Title = "JNukeCrypt - Original Keys";
        Console.OutputEncoding = Encoding.UTF8;

        ShowBanner();

        if (args.Length == 0)
        {
            Console.WriteLine("Arraste arquivos .dat, .u, .ukx ou .utx sobre o JNukeCrypt.exe.");
            Console.WriteLine();
            Console.WriteLine("O programa detecta automaticamente se deve ENCRYPTAR ou DECRYPTAR.");
            Console.WriteLine();
            Console.WriteLine("Pressione qualquer tecla para fechar...");
            Console.ReadKey(true);
            return 0;
        }

        int errors = 0;

        foreach (string rawPath in args)
        {
            string path = rawPath.Trim().Trim('"');

            if (!File.Exists(path))
            {
                PrintError(Path.GetFileName(path), "Arquivo nao encontrado.");
                errors++;
                continue;
            }

            string ext = Path.GetExtension(path);
            if (!SupportedExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"IGNORADO: {Path.GetFileName(path)}");
                Console.WriteLine("Extensao nao suportada. Use .dat, .u, .ukx ou .utx.");
                Console.ResetColor();
                Console.WriteLine();
                continue;
            }

            try
            {
                ProcessFile(path);
            }
            catch (Exception ex)
            {
                PrintError(Path.GetFileName(path), ex.Message);
                errors++;
            }
        }

        Console.WriteLine();
        Console.WriteLine("Pressione qualquer tecla para continuar. . .");
        Console.ReadKey(true);

        return errors == 0 ? 0 : 10;
    }

    private static void ProcessFile(string path)
    {
        byte[] input = File.ReadAllBytes(path);

        bool currentlyUnlocked = StartsWith(input, Ver413Header);
        byte[] output = Transform(input);
        bool outputUnlocked = StartsWith(output, Ver413Header);

        string action;

        if (currentlyUnlocked)
        {
            action = "ENCRYPTED";
        }
        else if (outputUnlocked)
        {
            action = "DECRYPTED";
        }
        else
        {
            throw new InvalidDataException(
                "Arquivo nao reconhecido como Lineage2Ver413 original ou 413 encryptado.");
        }

        WriteAtomic(path, output);

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"Processing file: {path}");
        Console.ResetColor();

        PrintStatus(action);
    }

    private static byte[] Transform(byte[] data)
    {
        byte[] output = new byte[data.Length];

        for (int pos = 0; pos < data.Length; pos++)
        {
            int block = pos / 256;
            int off = pos % 256;
            byte mask;

            if (block == 0)
            {
                mask = SpecialFirst[off];
            }
            else
            {
                byte[] key = ((block - 1) % 3) switch
                {
                    0 => K1,
                    1 => K2,
                    _ => K3
                };
                mask = key[off];
            }

            output[pos] = (byte)(data[pos] ^ mask);
        }

        return output;
    }

    private static bool StartsWith(byte[] data, byte[] signature)
    {
        if (data.Length < signature.Length)
            return false;

        for (int i = 0; i < signature.Length; i++)
        {
            if (data[i] != signature[i])
                return false;
        }

        return true;
    }

    private static void WriteAtomic(string path, byte[] data)
    {
        string dir = Path.GetDirectoryName(path) ?? ".";
        string temp = Path.Combine(
            dir,
            "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");

        try
        {
            File.WriteAllBytes(temp, data);
            File.Move(temp, path, true);
        }
        finally
        {
            if (File.Exists(temp))
                File.Delete(temp);
        }
    }

    private static void ShowBanner()
    {
        try
        {
            int width = Math.Min(92, Console.LargestWindowWidth);
            int height = Math.Min(24, Console.LargestWindowHeight);

            Console.SetWindowSize(width, height);
            Console.SetBufferSize(width, Math.Max(height, 120));
        }
        catch { }

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

    private static void PrintStatus(string action)
    {
        Console.WriteLine();

        if (action == "ENCRYPTED")
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(" ---------------------------------");
            Console.WriteLine("|   File successfully encrypted!  |");
            Console.WriteLine(" ---------------------------------");
        }
        else if (action == "DECRYPTED")
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" ---------------------------------");
            Console.WriteLine("|  File successfully de-crypted!  |");
            Console.WriteLine(" ---------------------------------");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(" ---------------------------------");
            Console.WriteLine("|   File successfully crypted!    |");
            Console.WriteLine(" ---------------------------------");
        }

        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintError(string file, string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"ERRO: {file}");
        Console.WriteLine(message);
        Console.ResetColor();
        Console.WriteLine();
    }
}