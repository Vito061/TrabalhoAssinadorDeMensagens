import os
import struct
import sys

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def shr(x, n):
    return (x >> n)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def gamma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def manual_sha256(message_bytes):
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    length = len(message_bytes) * 8
    message_bytes += b'\x80'
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    message_bytes += struct.pack('>Q', length)
    for i in range(0, len(message_bytes), 64):
        block = message_bytes[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = struct.unpack('>I', block[j*4:(j+1)*4])[0]
        for j in range(16, 64):
            w[j] = (gamma1(w[j-2]) + w[j-7] + gamma0(w[j-15]) + w[j-16]) & 0xffffffff
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            t1 = (h + sigma1(e) + ch(e, f, g) + K[j] + w[j]) & 0xffffffff
            t2 = (sigma0(a) + maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        H[0] = (H[0] + a) & 0xffffffff
        H[1] = (H[1] + b) & 0xffffffff
        H[2] = (H[2] + c) & 0xffffffff
        H[3] = (H[3] + d) & 0xffffffff
        H[4] = (H[4] + e) & 0xffffffff
        H[5] = (H[5] + f) & 0xffffffff
        H[6] = (H[6] + g) & 0xffffffff
        H[7] = (H[7] + h) & 0xffffffff
    return b''.join(struct.pack('>I', h) for h in H)

def gcd_extended(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = gcd_extended(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    gcd, x, y = gcd_extended(a, m)
    if gcd != 1:
        raise Exception('Inverso modular não existe')
    else:
        return (x % m + m) % m

def is_prime(n):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi <= e or gcd_extended(e, phi)[0] != 1:
        e = 3
        while gcd_extended(e, phi)[0] != 1:
            e += 2
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt_decrypt(message_int, key, n):
    return pow(message_int, key, n)

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def menu():
    print("\n--- ASSINADOR DIGITAL ---")
    print("1. Gerar Chaves RSA")
    print("2. Assinar Mensagem")
    print("3. Validar Assinatura")
    print("0. Sair")
    return input("Escolha uma opção: ")

def main():
    public_key = None
    private_key = None

    PRIME_P = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    PRIME_Q = 115792089237316195423570985008687907853269984665640564039457584007913129639579

    while True:
        op = menu()

        if op == '1':
            print("\n--- GERAÇÃO DE CHAVES ---")
            print("Para funcionar com SHA-256, precisamos de números primos muito grandes.")
            print("Pressione [Enter] para usar primos automáticos (recomendado).")
            print("Ou digite 'M' para inserir manualmente.")
            choice = input("Sua escolha: ").strip().lower()

            if choice == 'm':
                try:
                    p_str = input("Digite o primo 'p': ")
                    q_str = input("Digite o primo 'q': ")
                    p = int(p_str)
                    q = int(q_str)
                except ValueError:
                    print("Erro: Números inválidos.")
                    continue
            else:
                print("Usando primos de teste automáticos...")
                p = PRIME_P
                q = PRIME_Q

            try:
                print("Gerando chaves... (isso pode levar um segundo)")
                pub, priv = generate_keypair(p, q)
                public_key = pub
                private_key = priv
                print("\n>>> CHAVES GERADAS COM SUCESSO! <<<")
                print("Agora você pode usar as opções 2 e 3.")
            except Exception as e:
                print(f"Erro na geração: {e}")

        elif op == '2':
            if not private_key:
                print("\n[!] ERRO: Você precisa gerar as chaves primeiro (Opção 1).")
                continue
            
            print("\n--- ASSINAR MENSAGEM ---")
            msg = input("Digite a mensagem para assinar: ")
            msg_bytes = msg.encode('utf-8')
            
            msg_hash = manual_sha256(msg_bytes)
            hash_int = bytes_to_int(msg_hash)

            if hash_int >= private_key[1]:
                print("\n[!] ERRO CRÍTICO: As chaves são muito pequenas para este hash.")
                print("Gere novas chaves na Opção 1 (use [Enter] para o modo automático).")
                continue

            signature_int = rsa_encrypt_decrypt(hash_int, private_key[0], private_key[1])
            signature_hex = hex(signature_int)[2:]
            
            print(f"\n[RESULTADO] Assinatura Digital (copie isto):\n{signature_hex}")

        elif op == '3':
            if not public_key:
                print("\n[!] ERRO: Gere as chaves primeiro (Opção 1).")
                continue
                
            print("\n--- VALIDAR ASSINATURA ---")
            msg = input("Digite a mensagem original: ")
            sig_hex = input("Cole a assinatura digital (hex): ").strip()

            try:
                msg_bytes = msg.encode('utf-8')
                calculated_hash_int = bytes_to_int(manual_sha256(msg_bytes))
                sig_int = int(sig_hex, 16)
                decrypted_hash_int = rsa_encrypt_decrypt(sig_int, public_key[0], public_key[1])
                
                if calculated_hash_int == decrypted_hash_int:
                    print("\n>>> SUCESSO: A ASSINATURA É VÁLIDA! <<<")
                    print("A mensagem é autêntica.")
                else:
                    print("\n>>> FALHA: A ASSINATURA É INVÁLIDA! <<<")
                    print("A mensagem pode ter sido alterada.")
            except Exception:
                print("\n[!] Erro na validação. Verifique a assinatura colada.")

        elif op == '0':
            print("Encerrando...")
            break
        else:
            print("Opção inválida.")

if __name__ == '__main__':
    main()
