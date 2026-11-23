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


def text_to_decimal_blocks(text, n, block_size=3):
    """Encode each character as a fixed-width 3-digit Unicode code point.

    Examples: H -> 072, h -> 104, i -> 105. The resulting decimal
    stream is split into 3-digit RSA plaintext blocks.
    """
    if not text:
        raise ValueError("Pesan tidak boleh kosong.")

    unsupported = [(char, ord(char)) for char in text if ord(char) > 999]
    if unsupported:
        shown = ", ".join(f"{char!r}={code}" for char, code in unsupported[:4])
        raise ValueError(
            "Metode 3 digit hanya menerima karakter dengan kode 000-999. "
            f"Karakter tidak valid: {shown}"
        )

    codes = [f"{ord(char):03d}" for char in text]
    digit_string = "".join(codes)
    raw_blocks = [
        digit_string[index:index + block_size]
        for index in range(0, len(digit_string), block_size)
    ]
    values = [int(block) for block in raw_blocks]

    invalid = [
        (index + 1, block, value)
        for index, (block, value) in enumerate(zip(raw_blocks, values))
        if value >= n
    ]
    if invalid:
        index, block, value = invalid[0]
        raise ValueError(
            f"Blok ke-{index} ({block} = {value}) harus lebih kecil dari n = {n}. "
            "Pilih p dan q yang menghasilkan n lebih besar."
        )

    return {
        "ascii_codes": codes,
        "digit_string": digit_string,
        "raw_blocks": raw_blocks,
        "display_blocks": raw_blocks,
        "values": values,
        "lengths": [3] * len(raw_blocks),
        "block_size": block_size,
    }


def decimal_blocks_to_text(values, lengths=None):
    """Decode fixed-width 3-digit code points back into text."""
    blocks = [f"{int(value):03d}" for value in values]
    codes = [int(block) for block in blocks]
    if any(code < 0 or code > 999 for code in codes):
        raise ValueError("Kode hasil dekripsi berada di luar rentang 000-999.")
    return "".join(chr(code) for code in codes), blocks, blocks

def encrypt_blocks(blocks,e,n):
    if any(v<0 or v>=n for v in blocks): raise ValueError("Setiap blok harus memenuhi 0 <= blok < n.")
    return [pow(v,e,n) for v in blocks]

def decrypt_blocks(blocks,d,n):
    if any(v<0 or v>=n for v in blocks): raise ValueError("Setiap cipher harus memenuhi 0 <= cipher < n.")
    return [pow(v,d,n) for v in blocks]
