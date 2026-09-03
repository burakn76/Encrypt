JNukeCrypt - Encrypt / Decrypt de arquivos Lineage 2 (Interlude / 41x)

ESQUEMA DE CRIPTOGRAFIA
-----------------------
Blowfish (formato Lineage 2 familia 41x), com a variante "blowfish-compat"
usada pelo cliente (blocos de 8 bytes em little-endian, modo ECB).

Layout do arquivo encryptado:
  [ header "Lineage2Ver413" em UTF-16LE (28 bytes, texto claro) ]
  [ corpo cifrado com Blowfish                                  ]

Extensoes suportadas:
  .dat  .u  .ukx  .utx

FUNCIONAMENTO
-------------
- Arraste um ou varios arquivos sobre o JNukeCrypt.exe.
- Deteccao automatica:
    * Se o arquivo NAO tem o header Lineage2Ver413 -> ENCRYPT
      (adiciona o header e cifra o corpo com Blowfish).
    * Se o arquivo JA tem o header Lineage2Ver413 -> DECRYPT
      (remove o header e decifra o corpo).
- O arquivo e alterado no proprio local (gravacao atomica).

CHAVE DO SEU SERVIDOR (IMPORTANTE)
----------------------------------
A chave fica em src/Blowfish/L2ServerKey.cs, na constante KeyText.

  >>> TROQUE o valor de KeyText por uma frase secreta e unica sua. <<<

A MESMA chave precisa ser usada no lado que decripta no cliente
(ver fachada em src/Launcher_Private413_Crypto.cs).

Nunca compartilhe sua chave. Quem tiver a chave consegue decriptar
os seus arquivos.

COMPILAR
--------
Rode o BUILD_RELEASE.bat (requer .NET 8 SDK). Gera:
  bin\Release\net8.0\win-x64\publish\JNukeCrypt.exe

ORGANIZACAO DO CODIGO
---------------------
  Program.cs                          -> entrada (parsing de args)
  src/ConsoleUI.cs                    -> banner e mensagens
  src/FileProcessor.cs                -> I/O e deteccao encrypt/decrypt
  src/Launcher_Private413_Crypto.cs   -> fachada p/ o cliente (mesmo esquema)
  src/Blowfish/BlowfishEngine.cs      -> cifrador Blowfish (nucleo)
  src/Blowfish/BlowfishTables.cs      -> tabelas P/S canonicas (pi)
  src/Blowfish/L2BlowfishCipher.cs    -> ECB + blowfish-compat (little-endian)
  src/Blowfish/L2FileFormatBlowfish.cs-> header + corpo cifrado
  src/Blowfish/L2ServerKey.cs         -> SUA chave (troque aqui)
