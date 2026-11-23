import html
import json
from math import gcd

import streamlit as st

from src.rsa_math import (
    decimal_blocks_to_text,
    decrypt_blocks,
    encrypt_blocks,
    generate_key_data,
    is_prime,
    text_to_decimal_blocks,
    valid_e_values,
)

st.set_page_config(page_title="RSA Encryptor", page_icon="🔐", layout="centered")

st.markdown("""
<style>
:root{--ink:#121212;--paper:#f4f1e8;--white:#fff;--acid:#dfff4f;--pink:#ff8fb3;--blue:#76d7ff;--muted:#5e5b55;--shadow:6px 6px 0 var(--ink)}
[data-testid="stAppViewContainer"]{background-color:var(--paper);background-image:linear-gradient(#1212120a 1px,transparent 1px),linear-gradient(90deg,#1212120a 1px,transparent 1px);background-size:26px 26px}
[data-testid="stHeader"]{background:transparent}.block-container{max-width:820px;padding:1.8rem 1rem 4rem}
h1,h2{color:var(--ink)!important;letter-spacing:-.045em}h1{font-size:clamp(2.8rem,8vw,5rem)!important;line-height:.92!important;margin:0!important;font-weight:950!important}h2{font-size:1.25rem!important;margin:0!important}p,.stCaption{color:var(--muted)}
.mast{border:3px solid var(--ink);background:var(--white);box-shadow:9px 9px 0 var(--ink);padding:1.4rem;margin-bottom:1.65rem;position:relative}.mast:after{content:'RSA';position:absolute;right:18px;top:14px;background:var(--pink);border:2px solid var(--ink);padding:.3rem .55rem;font-size:.72rem;font-weight:950;transform:rotate(2deg)}.mast p{margin:.75rem 0 0;max-width:520px}
.card{border:3px solid var(--ink);background:var(--white);box-shadow:var(--shadow);padding:1.15rem;margin:1.25rem 0}.card-head{display:flex;align-items:center;gap:.7rem;border-bottom:2px solid var(--ink);padding-bottom:.8rem;margin-bottom:1rem}.step{width:31px;height:31px;display:grid;place-items:center;background:var(--acid);border:2px solid var(--ink);font-weight:950}.prime-preview{border:2px solid var(--ink);background:#fff9c9;padding:.65rem .75rem;margin-top:.45rem;font-size:.82rem}.prime-preview.ok{background:#dcfce7}.prime-preview.bad{background:#ffe2e2}.prime-preview b{color:var(--ink)}.chips{display:flex;gap:.38rem;flex-wrap:wrap;margin-top:.45rem}.chip{border:2px solid var(--ink);background:var(--white);padding:.22rem .48rem;font-size:.78rem;font-weight:850;box-shadow:2px 2px 0 var(--ink)}
.keys{display:grid;grid-template-columns:1fr 1fr;gap:.8rem;margin-top:1rem}.key{border:2px solid var(--ink);padding:.85rem}.key.public{background:var(--blue)}.key.private{background:var(--pink)}.key small{font-weight:900;text-transform:uppercase}.key strong{display:block;font-size:1.15rem;margin-top:.2rem;overflow-wrap:anywhere}.capacity{border:2px solid var(--ink);padding:.7rem;margin-top:.8rem;background:var(--acid);font-weight:800}.output{border:2px solid var(--ink);background:#f9f9f9;padding:.8rem;font-family:ui-monospace,monospace;overflow-wrap:anywhere}.result{background:var(--acid);font-family:inherit;font-weight:850}
.stButton>button,.stDownloadButton>button{border:3px solid var(--ink)!important;border-radius:0!important;background:var(--acid)!important;color:var(--ink)!important;font-weight:900!important;min-height:2.8rem;box-shadow:4px 4px 0 var(--ink)!important}.stButton>button:hover,.stDownloadButton>button:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 var(--ink)!important}.stNumberInput input,.stTextArea textarea,.stSelectbox>div>div{border:3px solid var(--ink)!important;border-radius:0!important;background:#fff!important}.stAlert{border:3px solid var(--ink);border-radius:0}.stExpander{border:2px solid var(--ink)!important;border-radius:0!important;background:#fff}.footer{font-size:.75rem;color:var(--muted);margin-top:1.5rem;text-align:center}@media(max-width:600px){.keys{grid-template-columns:1fr}.mast{box-shadow:6px 6px 0 var(--ink)}.mast:after{display:none}}
</style>
""", unsafe_allow_html=True)

for name,value in {"rsa_key":None,"cipher":[],"cipher_chars":"","lengths":[],"details":None,"plain":""}.items():
    st.session_state.setdefault(name,value)


def nearest_primes(value, minimum=2, maximum=10000, exclude=None):
    lower=value-1
    while lower>=minimum and (not is_prime(lower) or lower==exclude): lower-=1
    upper=value+1
    while upper<=maximum and (not is_prime(upper) or upper==exclude): upper+=1
    return (lower if lower>=minimum else None, upper if upper<=maximum else None)


def prime_preview(label, value, exclude=None):
    if value is None:
        st.markdown(f'<div class="prime-preview"><b>{label}</b> · Ketik angka 2-10.000. Prima terdekat akan muncul di sini.</div>',unsafe_allow_html=True)
        return False
    value=int(value)
    if is_prime(value) and value!=exclude:
        st.markdown(f'<div class="prime-preview ok"><b>{value}</b> adalah bilangan prima ✓</div>',unsafe_allow_html=True)
        return True
    lower,upper=nearest_primes(value,exclude=exclude)
    chips="".join(f'<span class="chip">{item:,}</span>'.replace(",",".") for item in (lower,upper) if item is not None)
    reason="sama dengan nilai lainnya" if value==exclude else "bukan bilangan prima"
    st.markdown(f'<div class="prime-preview bad"><b>{value}</b> {reason}.<div class="chips">Prima terdekat: {chips}</div></div>',unsafe_allow_html=True)
    return False


def cipher_chars(values):
    return "".join(chr(v) if 0<=v<=0x10FFFF and not 0xD800<=v<=0xDFFF else "�" for v in values)

st.markdown('<div class="mast"><h1>Enkripsi RSA</h1><p>Buat kunci, enkripsi pesan, dan kembalikan ciphertext menjadi teks.</p></div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">1</div><h2>Kunci RSA</h2></div>',unsafe_allow_html=True)
p_col,q_col=st.columns(2,gap="medium")
with p_col:
    p=st.number_input("Bilangan prima p",min_value=2,max_value=10000,step=1,value=None,placeholder="2-10.000",key="p_value")
    p_ok=prime_preview("p",p,exclude=int(st.session_state.q_value) if st.session_state.get("q_value") else None)
with q_col:
    q=st.number_input("Bilangan prima q",min_value=2,max_value=10000,step=1,value=None,placeholder="2-10.000",key="q_value")
    q_ok=prime_preview("q",q,exclude=int(p) if p is not None else None)

valid=p_ok and q_ok and int(p)!=int(q)
if valid:
    p_i,q_i=int(p),int(q); n=p_i*q_i; phi=(p_i-1)*(q_i-1)
    options=valid_e_values(phi)
    e=st.selectbox("Eksponen publik e",options)
    grade="Mendukung seluruh kode karakter 000-999" if n>999 else f"Hanya mendukung kode karakter di bawah {n}"
    st.markdown(f'<div class="capacity">n = {n:,} · φ(n) = {phi:,} · {grade}</div>'.replace(",","."),unsafe_allow_html=True)
    if st.button("Buat kunci",use_container_width=True):
        st.session_state.rsa_key=generate_key_data(p_i,q_i,e)
        st.session_state.cipher=[];st.session_state.plain="";st.rerun()

key=st.session_state.rsa_key
if key:
    current=valid and (int(p),int(q))==(key["p"],key["q"])
    if not current: st.warning("Nilai p atau q berubah. Buat kunci ulang.")
    st.markdown(f'<div class="keys"><div class="key public"><small>Publik</small><strong>({key["e"]}, {key["n"]})</strong></div><div class="key private"><small>Privat</small><strong>({key["d"]}, {key["n"]})</strong></div></div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">2</div><h2>Enkripsi</h2></div>',unsafe_allow_html=True)
message=st.text_area("Pesan",height=95,placeholder="Tulis pesan")
key_current=bool(key) and valid and (int(p),int(q))==(key["p"],key["q"])
max_code=max((ord(ch) for ch in message),default=0)
compatible=key_current and bool(message) and max_code<=999 and max_code<key["n"]
if message and key_current and not compatible:
    if max_code>999: st.error(f"Pesan memuat kode {max_code}; format ini mendukung maksimal 999.")
    else: st.error(f"n = {key['n']} terlalu kecil. Pesan membutuhkan n > {max_code}.")
if st.button("Enkripsi",use_container_width=True,disabled=not compatible):
    data=text_to_decimal_blocks(message,key["n"],3)
    cipher=encrypt_blocks(data["values"],key["e"],key["n"])
    st.session_state.cipher=cipher;st.session_state.cipher_chars=cipher_chars(cipher)
    st.session_state.lengths=data["lengths"];st.session_state.details=data;st.session_state.plain="";st.rerun()
if st.session_state.cipher:
    st.caption("Tampilan ciphertext")
    st.markdown(f'<div class="output">{html.escape(st.session_state.cipher_chars)}</div>',unsafe_allow_html=True)
    st.caption("Ciphertext angka")
    st.markdown(f'<div class="output">{" ".join(map(str,st.session_state.cipher))}</div>',unsafe_allow_html=True)
    with st.expander("Detail kode"):
        st.write(" ".join(st.session_state.details["ascii_codes"]))
    st.download_button("Unduh ciphertext",json.dumps({"cipher":st.session_state.cipher,"lengths":st.session_state.lengths},indent=2),"ciphertext.json","application/json",use_container_width=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">3</div><h2>Dekripsi</h2></div>',unsafe_allow_html=True)
if st.button("Dekripsi",use_container_width=True,disabled=not key_current or not st.session_state.cipher):
    blocks=decrypt_blocks(st.session_state.cipher,key["d"],key["n"])
    st.session_state.plain,_,_=decimal_blocks_to_text(blocks,st.session_state.lengths);st.rerun()
if st.session_state.plain:
    st.markdown(f'<div class="output result">{html.escape(st.session_state.plain)}</div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)
st.markdown('<div class="footer">RSA demonstrasi · ciphertext angka digunakan untuk dekripsi</div>',unsafe_allow_html=True)
