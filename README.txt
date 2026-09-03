JNukeCrypt Private - Detecta Encrypt / Decrypt

Extensoes:
.dat
.u
.ukx
.utx

Funcionamento:
- Arraste um ou varios arquivos sobre JNukeCrypt.exe.
- Sem confirmacao.
- Se o arquivo estiver original/desbloqueado (header Lineage2Ver413),
  o JNUKE mostra FILE SUCCESSFULLY ENCRYPTED / ARQUIVO BLOQUEADO.
- Se o arquivo estiver encryptado e a transformacao restaurar Lineage2Ver413,
  mostra FILE SUCCESSFULLY DECRYPTED / ARQUIVO DESBLOQUEADO.
- O arquivo e alterado no proprio local.

Compile com BUILD_RELEASE.bat.


JNukeCrypt SmartStyle - 413 COMPATIBLE
--------------------------------------
Esta build foi ajustada para o conjunto 413 validado no L2.

Detecção:
- Se começa com Lineage2Ver413 (UTF-16LE): ENCRYPT
- Se a transformação restaura Lineage2Ver413: DECRYPT
- Se nenhum dos dois casos ocorrer: NÃO ALTERA o arquivo e mostra erro.

Extensões:
.dat / .u / .ukx / .utx

IMPORTANTE:
Esta é a variante de compatibilidade 413. Ela usa o mesmo esquema que já
foi validado com o par original/encryptado anteriormente.
