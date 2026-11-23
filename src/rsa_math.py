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
    if not text: raise ValueError("Pesan tidak boleh kosong.")
    bad=[(ch,ord(ch)) for ch in text if not 32 <= ord(ch) <= 99]
    if bad: raise ValueError("Metode PPT hanya menerima ASCII 2 digit (32-99). Karakter tidak valid: "+", ".join(f"{ch!r}={code}" for ch,code in bad[:4]))
    codes=[str(ord(ch)) for ch in text]
    digits="".join(codes)
    raw=[digits[i:i+block_size] for i in range(0,len(digits),block_size)]
    values=[int(x) for x in raw]
    invalid=[(i+1,x,v) for i,(x,v) in enumerate(zip(raw,values)) if v>=n]
    if invalid:
        i,x,v=invalid[0]; raise ValueError(f"Blok ke-{i} ({x}={v}) harus lebih kecil dari n={n}. Pilih p dan q lebih besar.")
    return {"ascii_codes":codes,"digit_string":digits,"raw_blocks":raw,"display_blocks":[x.zfill(block_size) for x in raw],"values":values,"lengths":[len(x) for x in raw]}

def decimal_blocks_to_text(values, lengths):
    raw=[str(v).zfill(l) for v,l in zip(values,lengths)]
    digits="".join(raw)
    if len(digits)%2: raise ValueError("Jumlah digit hasil dekripsi tidak genap.")
    codes=[digits[i:i+2] for i in range(0,len(digits),2)]
    if any(not 32<=int(x)<=99 for x in codes): raise ValueError("Kode ASCII hasil dekripsi di luar 32-99.")
    return "".join(chr(int(x)) for x in codes),raw,codes

def encrypt_blocks(blocks,e,n):
    if any(v<0 or v>=n for v in blocks): raise ValueError("Setiap blok harus memenuhi 0 <= blok < n.")
    return [pow(v,e,n) for v in blocks]

def decrypt_blocks(blocks,d,n):
    if any(v<0 or v>=n for v in blocks): raise ValueError("Setiap cipher harus memenuhi 0 <= cipher < n.")
    return [pow(v,d,n) for v in blocks]
