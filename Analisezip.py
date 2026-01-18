import zipfile
import struct
import sys
from datetime import datetime

ZIP_LOCAL_FILE_HEADER = b"\x50\x4b\x03\x04"

def analyze_zip(zip_path):
    print(f"\n[+] Analisando arquivo: {zip_path}\n")

    # 1. Tentativa com zipfile (mesmo se estiver parcialmente corrompido)
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            print("[*] Arquivos encontrados via zipfile:\n")
            for info in z.infolist():
                print(f"Nome do arquivo : {info.filename}")
                print(f"Tamanho compactado : {info.compress_size} bytes")
                print(f"Tamanho real : {info.file_size} bytes")
                print(f"Data modificação : {datetime(*info.date_time)}")
                print(f"Flag suspeita (executável) : {info.filename.lower().endswith(('.exe','.js','.bat','.scr'))}")
                print("-" * 50)
            return
    except Exception as e:
        print("[!] zipfile falhou (ZIP possivelmente corrompido)")
        print(f"    Erro: {e}\n")

    # 2. Parsing manual de cabeçalhos ZIP
    print("[*] Tentando parsing manual dos cabeçalhos ZIP...\n")

    with open(zip_path, "rb") as f:
        data = f.read()

    offset = 0
    found = False

    while True:
        offset = data.find(ZIP_LOCAL_FILE_HEADER, offset)
        if offset == -1:
            break

        found = True

        header = data[offset + 4: offset + 30]
        try:
            (
                version,
                flags,
                compression,
                mod_time,
                mod_date,
                crc,
                comp_size,
                uncomp_size,
                name_len,
                extra_len
            ) = struct.unpack("<HHHHHIIIHH", header)

            name_start = offset + 30
            name_end = name_start + name_len
            filename = data[name_start:name_end].decode(errors="replace")

            print(f"Arquivo encontrado : {filename}")
            print(f"Tamanho compactado : {comp_size} bytes")
            print(f"Tamanho real : {uncomp_size} bytes")
            print(f"Compressão : {compression}")
            print(f"Possível executável : {filename.lower().endswith(('.exe','.js','.bat','.scr'))}")
            print("-" * 50)

            offset = name_end + extra_len
        except Exception:
            offset += 4

    if not found:
        print("[!] Nenhum cabeçalho ZIP válido encontrado.")

    # 3. Fallback simples com strings
    print("\n[*] Fallback: procurando nomes suspeitos via strings...\n")

    suspicious_ext = (b".exe", b".js", b".bat", b".scr", b".dll")
    for ext in suspicious_ext:
        if ext in data.lower():
            print(f"[!] Possível referência encontrada para extensão: {ext.decode()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analyze_corrupted_zip.py <arquivo.zip>")
        sys.exit(1)

    analyze_zip(sys.argv[1])
