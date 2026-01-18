# Corrupted ZIP Analyzer

Este script Python permite analisar arquivos ZIP corrompidos e extrair informações sobre os arquivos contidos, incluindo nomes, tamanhos e extensões suspeitas, mesmo quando o arquivo ZIP não pode ser aberto normalmente.

Ele é útil para **análise de malware**, investigação de arquivos suspeitos e incident response.

---

## Funcionalidades

* Identifica arquivos dentro de ZIP mesmo quando o diretório central está corrompido.
* Exibe metadados dos arquivos:

  * Nome do arquivo
  * Tamanho compactado
  * Tamanho real
  * Data de modificação
  * Compressão
* Identifica possíveis arquivos maliciosos com extensões como:

  * `.exe`, `.js`, `.bat`, `.scr`, `.dll`
* Fallback com análise de strings quando os cabeçalhos ZIP estão severamente corrompidos.
* Seguro: não extrai nem executa nenhum arquivo dentro do ZIP.

---

## Requisitos

* Python 3.7 ou superior
* Bibliotecas padrão do Python (nenhuma instalação adicional necessária)

---

## Uso

```bash
python analyze_corrupted_zip.py <arquivo.zip>
```

**Exemplo:**

```bash
python analyze_corrupted_zip.py suspeito.zip
```

---

## Estrutura do Script

1. **Tentativa com `zipfile`**

   * Lê arquivos e metadados via API padrão do Python.

2. **Parsing manual dos cabeçalhos ZIP**

   * Procura por `Local File Header` (`0x04034b50`) e recupera nomes e metadados.

3. **Fallback via strings**

   * Procura extensões comuns de arquivos executáveis maliciosos.

---

## Saída Esperada

* List
