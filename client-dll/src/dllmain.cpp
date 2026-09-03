// ============================================================================
//  ogg.dll (proxy) - Protecao de arquivos do cliente Lineage 2 (Interlude/41x)
//
//  Funcionamento:
//   - As funcoes de audio (libogg) sao reexportadas via forwarding para
//     ogg_real.dll (ver ogg.def), entao o som do jogo continua normal.
//   - Ao carregar, fazemos IAT hook de CreateFileW/CreateFileA no processo.
//   - Quando o cliente abre um arquivo alvo (.dat/.u/.ukx/.utx) que comeca
//     com o header "Lineage2Ver413", a DLL le o arquivo, DECRIPTA na memoria
//     com Blowfish + a chave privada (config.h) e grava uma copia temporaria
//     decifrada; o handle devolvido ao jogo aponta para essa copia.
//   - Como a chave esta apenas aqui e no seu encryptor, ferramentas de
//     terceiros (ex.: SmartCrypt) nao conseguem decriptar seus arquivos.
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cwchar>

#include "config.h"
#include "blowfish.h"
#include "iat_hook.h"

// -------- header Lineage2Ver413 em UTF-16LE (28 bytes) --------
static const wchar_t kHeaderText[] = L"Lineage2Ver413";
static const size_t  kHeaderBytes  = (sizeof(kHeaderText) - 1) * sizeof(wchar_t); // 28

// -------- ponteiros para as funcoes originais --------
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                      DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                      DWORD, DWORD, HANDLE);

static CreateFileW_t g_realCreateFileW = nullptr;
static CreateFileA_t g_realCreateFileA = nullptr;

// -------- util --------
static bool HasTargetExtension(const std::wstring& path)
{
    static const wchar_t* exts[] = L2_TARGET_EXTS;
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = path.substr(dot);
    // _wcsicmp ja compara sem diferenciar maiusculas/minusculas.
    for (const wchar_t* t : exts)
        if (_wcsicmp(ext.c_str(), t) == 0) return true;
    return false;
}

// Le o arquivo inteiro em memoria. Retorna false se nao conseguir.
static bool ReadWholeFile(LPCWSTR path, std::vector<BYTE>& out)
{
    HANDLE h = g_realCreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    out.resize((size_t)sz.QuadPart);

    DWORD read = 0;
    BOOL ok = TRUE;
    size_t done = 0;
    while (done < out.size())
    {
        DWORD chunk = (DWORD)min((size_t)(1u << 20), out.size() - done);
        if (!ReadFile(h, out.data() + done, chunk, &read, nullptr) || read == 0)
        { ok = (done + read == out.size()); break; }
        done += read;
    }
    CloseHandle(h);
    return ok && done == out.size();
}

// Verifica se o buffer comeca com o header Lineage2Ver413.
static bool HasHeader(const std::vector<BYTE>& buf)
{
    if (buf.size() < kHeaderBytes) return false;
    return memcmp(buf.data(), kHeaderText, kHeaderBytes) == 0;
}

// Cria um arquivo temporario com o conteudo ja decifrado e devolve o handle.
static HANDLE OpenDecryptedTemp(std::vector<BYTE>& encrypted)
{
    // Decripta IN-PLACE (sem segunda copia): opera sobre o corpo, logo apos
    // o header. Reduz o pico de memoria pela metade em arquivos grandes.
    BYTE* body = encrypted.data() + kHeaderBytes;
    size_t bodyLen = encrypted.size() - kHeaderBytes;

    static const char key[] = L2_SERVER_KEY;
    Blowfish bf(reinterpret_cast<const uint8_t*>(key), sizeof(key) - 1);
    bf.L2Decrypt(body, bodyLen);

    wchar_t tmpDir[MAX_PATH], tmpFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    GetTempFileNameW(tmpDir, L"l2p", 0, tmpFile);

    // FILE_SHARE_READ: permite que o client reabra/mapeie o arquivo por outro
    // handle sem sharing violation.
    HANDLE h = g_realCreateFileW(tmpFile, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ, nullptr,
                                 CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                                 nullptr);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    // Grava tudo, verificando short-write: se falhar, descarta o temp e
    // sinaliza falha para cair no fallback (arquivo original).
    size_t done = 0;
    while (done < bodyLen)
    {
        DWORD chunk = (DWORD)min((size_t)(1u << 20), bodyLen - done);
        DWORD written = 0;
        if (!WriteFile(h, body + done, chunk, &written, nullptr) || written == 0)
        {
            CloseHandle(h); // DELETE_ON_CLOSE remove o temp
            return INVALID_HANDLE_VALUE;
        }
        done += written;
    }

    SetFilePointer(h, 0, nullptr, FILE_BEGIN); // volta ao inicio p/ o jogo ler
    return h;
}

// -------- hooks --------
static HANDLE WINAPI HookedCreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                       LPSECURITY_ATTRIBUTES sa, DWORD disp,
                                       DWORD flags, HANDLE tmpl)
{
    // Toda a logica de decrypt roda dentro de try/catch: qualquer falha
    // (ex.: memoria insuficiente em arquivo grande) NUNCA pode escapar como
    // excecao C++ atraves da fronteira WINAPI. Em caso de erro, cai no
    // comportamento normal (abre o arquivo como esta).
    try
    {
        // Interessa: leitura de arquivos alvo. A decisao real e pelo HEADER,
        // nao pela disposition (evita pular OPEN_ALWAYS etc.).
        if (name && (access & GENERIC_READ) && HasTargetExtension(name))
        {
            std::vector<BYTE> raw;
            if (ReadWholeFile(name, raw) && HasHeader(raw))
            {
                HANDLE h = OpenDecryptedTemp(raw);
                if (h != INVALID_HANDLE_VALUE)
                    return h; // jogo le a versao decifrada, transparente
            }
            // Sem header ou falha -> comportamento normal abaixo.
        }
    }
    catch (...)
    {
        // Silenciosamente cai no fallback: nunca deixa a excecao propagar.
    }
    return g_realCreateFileW(name, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI HookedCreateFileA(LPCSTR name, DWORD access, DWORD share,
                                       LPSECURITY_ATTRIBUTES sa, DWORD disp,
                                       DWORD flags, HANDLE tmpl)
{
    if (name)
    {
        // Dimensiona o buffer pelo tamanho necessario (sem truncar caminhos longos).
        int need = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
        if (need > 0)
        {
            std::wstring wname((size_t)need, L'\0');
            if (MultiByteToWideChar(CP_ACP, 0, name, -1, &wname[0], need) > 0)
                return HookedCreateFileW(wname.c_str(), access, share, sa, disp, flags, tmpl);
        }
    }
    return g_realCreateFileA(name, access, share, sa, disp, flags, tmpl);
}

// -------- instalacao dos hooks --------
//
// O cliente L2 (Unreal Engine 2) carrega os pacotes (.u/.utx/.ukx) a partir
// de modulos da engine (Core.dll / Engine.dll), nao apenas do .exe. Por isso
// percorremos TODOS os modulos carregados e aplicamos o IAT hook em cada um
// que importe CreateFileW/CreateFileA.
static void InstallHooks()
{
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&InstallHooks), &self);

    // Guarda os ponteiros originais reais do kernel32 (fallback e chamadas
    // internas). Setados ANTES de qualquer patch para nao haver janela nula.
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    g_realCreateFileW = (CreateFileW_t)GetProcAddress(k32, "CreateFileW");
    g_realCreateFileA = (CreateFileA_t)GetProcAddress(k32, "CreateFileA");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do
        {
            // Nao faz hook na propria DLL nem no kernel32.
            if (me.hModule == self || me.hModule == k32)
                continue;

            HookImportedFunction(me.hModule, "kernel32.dll", "CreateFileW",
                                 (void*)HookedCreateFileW);
            HookImportedFunction(me.hModule, "kernel32.dll", "CreateFileA",
                                 (void*)HookedCreateFileA);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
    }
    return TRUE;
}
