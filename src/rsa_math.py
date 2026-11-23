from math import gcd, isqrt


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    limit = isqrt(n)
    factor = 3
    while factor <= limit:
        if n % factor == 0:
            return False
        factor += 2
    return True


def extended_gcd(a: int, b: int):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    steps = []
    while r:
        q = old_r // r
        steps.append((old_r, q, r, old_r % r))
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t, steps


def modular_inverse(e: int, phi: int) -> int:
    g, x, _, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e tidak memiliki balikan modulo phi(n).")
    return x % phi


def valid_e_values(phi: int, limit: int = 40):
    preferred = [3, 5, 17, 257, 65537]
    values = [e for e in preferred if 1 < e < phi and gcd(e, phi) == 1]
    candidate = 3
    while len(values) < limit and candidate < phi:
        if gcd(candidate, phi) == 1 and candidate not in values:
            values.append(candidate)
        candidate += 2
    return sorted(values)


def generate_key_data(p: int, q: int, e: int):
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p dan q wajib bilangan prima.")
    if p == q:
        raise ValueError("p dan q harus berbeda.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError("e harus memenuhi 1 < e < phi(n) dan PBB(e, phi(n)) = 1.")
    d = modular_inverse(e, phi)
    _, _, _, euclid_steps = extended_gcd(phi, e)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d, "euclid_steps": euclid_steps}


def max_chunk_bytes(n: int) -> int:
    if n <= 1:
        return 0
    return max(0, (n.bit_length() - 1) // 8)


def text_to_blocks(text: str, n: int):
    size = max_chunk_bytes(n)
    if size < 1:
        raise ValueError("n terlalu kecil untuk teks UTF-8. Pilih p dan q yang lebih besar atau gunakan mode angka.")
    raw = text.encode("utf-8")
    chunks = [raw[i:i + size] for i in range(0, len(raw), size)]
    blocks = [int.from_bytes(chunk, "big") for chunk in chunks]
    return blocks, [len(chunk) for chunk in chunks], size


def blocks_to_text(blocks, lengths):
    raw = b"".join(value.to_bytes(length, "big") for value, length in zip(blocks, lengths))
    return raw.decode("utf-8")


def encrypt_blocks(blocks, e: int, n: int):
    if any(value < 0 or value >= n for value in blocks):
        raise ValueError("Setiap blok plainteks harus memenuhi 0 <= blok < n.")
    return [pow(value, e, n) for value in blocks]


def decrypt_blocks(cipher_blocks, d: int, n: int):
    if any(value < 0 or value >= n for value in cipher_blocks):
        raise ValueError("Setiap blok cipherteks harus memenuhi 0 <= blok < n.")
    return [pow(value, d, n) for value in cipher_blocks]
