// Utilitario de IAT hooking: substitui, na Import Address Table de um modulo,
// o ponteiro de uma funcao importada por um ponteiro nosso.
#pragma once
#include <windows.h>

// Substitui, na IAT do modulo `module`, a entrada que aponta para a funcao
// `importName` importada de `dllName`, pelo ponteiro `hookFunc`.
// Retorna o ponteiro original (para encadear a chamada), ou nullptr se nao achou.
void* HookImportedFunction(HMODULE module,
                           const char* dllName,
                           const char* importName,
                           void* hookFunc);
