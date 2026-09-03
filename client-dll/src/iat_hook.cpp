#include "iat_hook.h"
#include <cstring>

void* HookImportedFunction(HMODULE module,
                           const char* dllName,
                           const char* importName,
                           void* hookFunc)
{
    if (!module) return nullptr;
    BYTE* base = reinterpret_cast<BYTE*>(module);

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return nullptr;

    auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);

    for (; imports->Name; ++imports)
    {
        const char* modName = reinterpret_cast<const char*>(base + imports->Name);
        if (_stricmp(modName, dllName) != 0)
            continue;

        // Os NOMES so podem ser lidos com seguranca pela OriginalFirstThunk
        // (INT). Numa imagem "bound", a FirstThunk (IAT) ja contem enderecos
        // resolvidos, nao RVAs de nome -> ler nomes de la daria lixo. Se nao
        // houver INT, nao da para casar por nome com seguranca: pula o modulo.
        if (imports->OriginalFirstThunk == 0)
            continue;

        auto origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + imports->OriginalFirstThunk);
        auto iatThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports->FirstThunk);

        for (; origThunk->u1.AddressOfData; ++origThunk, ++iatThunk)
        {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                continue; // importado por ordinal; ignoramos (buscamos por nome)

            auto byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                base + origThunk->u1.AddressOfData);

            if (std::strcmp(reinterpret_cast<const char*>(byName->Name), importName) != 0)
                continue;

            // Achou. Troca o ponteiro na IAT (tornando a pagina gravavel).
            void* original = reinterpret_cast<void*>(iatThunk->u1.Function);
            DWORD oldProtect;
            VirtualProtect(&iatThunk->u1.Function, sizeof(void*),
                           PAGE_READWRITE, &oldProtect);
            iatThunk->u1.Function = reinterpret_cast<ULONG_PTR>(hookFunc);
            VirtualProtect(&iatThunk->u1.Function, sizeof(void*),
                           oldProtect, &oldProtect);
            return original;
        }
    }
    return nullptr;
}
