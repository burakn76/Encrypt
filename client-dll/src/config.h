// ============================================================================
//  CONFIGURACAO DA PROTECAO  --  EDITE AQUI
// ============================================================================
//  A chave abaixo precisa ser EXATAMENTE a mesma usada no encryptor (C#),
//  em src/Blowfish/L2ServerKey.cs -> KeyText.
//
//  >>> TROQUE por uma frase secreta e unica do SEU servidor. <<<
//  Nunca divulgue esta chave; ela e o que impede ferramentas de terceiros
//  (como o SmartCrypt) de decriptar seus arquivos.
// ============================================================================
#pragma once

// Chave Blowfish (bytes UTF-8 da frase). Deve bater com o encryptor.
#define L2_SERVER_KEY "TROQUE_ESTA_CHAVE_DO_SEU_SERVIDOR_L2"

// Nome da DLL original (a libogg verdadeira, renomeada). A nossa DLL faz
// forwarding das funcoes de audio para ela.
#define L2_REAL_OGG_DLL "ogg_real.dll"

// Extensoes que devem ser decriptadas ao serem lidas pelo cliente.
// (Comparacao case-insensitive.)
#define L2_TARGET_EXTS { L".dat", L".u", L".ukx", L".utx" }
