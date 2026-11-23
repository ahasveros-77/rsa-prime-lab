import html
import json
from math import gcd, isqrt

import streamlit as st

from src.rsa_math import (
    decimal_blocks_to_text,
    decrypt_blocks,
    encrypt_blocks,
    generate_key_data,
    is_prime,
    text_to_decimal_blocks,
)

st.set_page_config(page_title="RSA Encryptor", page_icon="🔐", layout="centered")

st.markdown("""
<style>
:root{--ink:#121212;--paper:#f4f1e8;--white:#fff;--acid:#dfff4f;--pink:#ff8fb3;--blue:#76d7ff;--muted:#5e5b55;--shadow:6px 6px 0 var(--ink)}
[data-testid="stAppViewContainer"]{background-color:var(--paper);background-image:linear-gradient(#1212120a 1px,transparent 1px),linear-gradient(90deg,#1212120a 1px,transparent 1px);background-size:26px 26px}[data-testid="stHeader"]{background:transparent}.block-container{max-width:820px;padding:1.8rem 1rem 4rem}
h1,h2{color:var(--ink)!important;letter-spacing:-.045em}h1{font-size:clamp(2.8rem,8vw,5rem)!important;line-height:.92!important;margin:0!important;font-weight:950!important}h2{font-size:1.25rem!important;margin:0!important}p,.stCaption{color:var(--muted)}
.mast{border:3px solid var(--ink);background:var(--white);box-shadow:9px 9px 0 var(--ink);padding:1.4rem;margin-bottom:1.65rem;position:relative}.mast:after{content:'RSA';position:absolute;right:18px;top:14px;background:var(--pink);border:2px solid var(--ink);padding:.3rem .55rem;font-size:.72rem;font-weight:950;transform:rotate(2deg)}.mast p{margin:.75rem 0 0;max-width:520px}
.card{border:3px solid var(--ink);background:var(--white);box-shadow:var(--shadow);padding:1.15rem;margin:1.25rem 0}.card-head{display:flex;align-items:center;gap:.7rem;border-bottom:2px solid var(--ink);padding-bottom:.8rem;margin-bottom:1rem}.step{width:31px;height:31px;display:grid;place-items:center;background:var(--acid);border:2px solid var(--ink);font-weight:950}.rule{border:2px solid var(--ink);background:#fff9c9;padding:.72rem;margin:.65rem 0;font-weight:800}.status{border:2px solid var(--ink);padding:.58rem .7rem;margin-top:.45rem;font-size:.82rem}.status.ok{background:#dcfce7}.status.bad{background:#ffe2e2}.keys{display:grid;grid-template-columns:1fr 1fr;gap:.8rem;margin-top:1rem}.key{border:2px solid var(--ink);padding:.85rem}.key.public{background:var(--blue)}.key.private{background:var(--pink)}.key small{font-weight:900;text-transform:uppercase}.key strong{display:block;font-size:1.15rem;margin-top:.2rem;overflow-wrap:anywhere}.output{border:2px solid var(--ink);background:#f9f9f9;padding:.8rem;font-family:ui-monospace,monospace;overflow-wrap:anywhere}.result{background:var(--acid);font-family:inherit;font-weight:850}
.stButton>button,.stDownloadButton>button{border:3px solid var(--ink)!important;border-radius:0!important;background:var(--acid)!important;color:var(--ink)!important;font-weight:900!important;min-height:2.8rem;box-shadow:4px 4px 0 var(--ink)!important}.stButton>button:hover,.stDownloadButton>button:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 var(--ink)!important}.stTextArea textarea,.stNumberInput input{border:3px solid var(--ink)!important;border-radius:0!important;background:#fff!important}.stAlert{border:3px solid var(--ink);border-radius:0}.footer{font-size:.75rem;color:var(--muted);margin-top:1.5rem;text-align:center}@media(max-width:600px){.keys{grid-template-columns:1fr}.mast{box-shadow:6px 6px 0 var(--ink)}.mast:after{display:none}}
</style>
""", unsafe_allow_html=True)

for name,value in {"rsa_key":None,"cipher":[],"cipher_chars":"","lengths":[],"plain":"","key_signature":None}.items():
    st.session_state.setdefault(name,value)


def next_prime_at_least(value, exclude=None):
    candidate=max(2,int(value))
    while candidate<=10000:
        if candidate!=exclude and is_prime(candidate): return candidate
        candidate+=1
    return None


def recommended_pair(required_n):
    start=max(2,isqrt(required_n)+1)
    p=next_prime_at_least(start)
    q=next_prime_at_least(start,exclude=p)
    while p and q and p*q<=required_n:
        q=next_prime_at_least(q+1,exclude=p)
    return p,q


def choose_e(phi):
    for candidate in (65537,257,17,5,3):
        if 1<candidate<phi and gcd(candidate,phi)==1: return candidate
    return next(candidate for candidate in range(3,phi,2) if gcd(candidate,phi)==1)


def cipher_chars(values):
    return "".join(chr(v) if 0<=v<=0x10FFFF and not 0xD800<=v<=0xDFFF else "�" for v in values)


st.markdown('<div class="mast"><h1>Enkripsi RSA</h1><p>Masukkan pesan, tentukan p dan q, lalu enkripsi.</p></div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">1</div><h2>Pesan</h2></div>',unsafe_allow_html=True)
message=st.text_area("Pesan",height=105,placeholder="Tulis pesan",key="message")
codes=[ord(char) for char in message]
max_code=max(codes,default=0)
message_valid=bool(message) and max_code<=999
if max_code>999: st.error(f"Kode karakter {max_code} melebihi batas 999.")
elif message: st.markdown(f'<div class="rule">Syarat kunci: p × q &gt; {max_code}</div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">2</div><h2>Kunci RSA</h2></div>',unsafe_allow_html=True)
if not message_valid:
    st.info("Masukkan pesan terlebih dahulu.")
    p=q=None
else:
    rec_p,rec_q=recommended_pair(max_code)
    st.caption(f"Rekomendasi minimum: p = {rec_p}, q = {rec_q} (boleh pilih prima lain).")
    p_col,q_col=st.columns(2,gap="medium")
    with p_col:
        p=st.number_input("Bilangan prima p",min_value=2,max_value=10000,step=1,value=None,placeholder=f"Minimal contoh: {rec_p}")
        p_ok=p is not None and is_prime(int(p))
        if p is not None:
            st.markdown(f'<div class="status {"ok" if p_ok else "bad"}">{int(p)} {"prima ✓" if p_ok else "bukan prima"}</div>',unsafe_allow_html=True)
    with q_col:
        q=st.number_input("Bilangan prima q",min_value=2,max_value=10000,step=1,value=None,placeholder=f"Minimal contoh: {rec_q}")
        q_ok=q is not None and is_prime(int(q))
        if q is not None:
            st.markdown(f'<div class="status {"ok" if q_ok else "bad"}">{int(q)} {"prima ✓" if q_ok else "bukan prima"}</div>',unsafe_allow_html=True)

    pair_valid=p_ok and q_ok and int(p)!=int(q) and int(p)*int(q)>max_code
    if p_ok and q_ok:
        n=int(p)*int(q)
        if int(p)==int(q): st.error("p dan q harus berbeda.")
        elif n<=max_code: st.error(f"n = {n} belum valid. Gunakan p dan q sehingga n > {max_code}.")
        else: st.markdown(f'<div class="status ok">n = {n} valid ✓</div>',unsafe_allow_html=True)

    if pair_valid:
        p_i,q_i=int(p),int(q); phi=(p_i-1)*(q_i-1); e=choose_e(phi)
        signature=(p_i,q_i,e,message)
        if st.button("Buat kunci",use_container_width=True):
            st.session_state.rsa_key=generate_key_data(p_i,q_i,e)
            st.session_state.key_signature=signature
            st.session_state.cipher=[];st.session_state.plain="";st.rerun()
    else:
        signature=None

key=st.session_state.rsa_key
key_current=bool(key) and signature is not None and st.session_state.key_signature==signature
if key:
    if not key_current: st.warning("Pesan atau nilai prima berubah. Buat kunci ulang.")
    st.markdown(f'<div class="keys"><div class="key public"><small>Publik</small><strong>({key["e"]}, {key["n"]})</strong></div><div class="key private"><small>Privat</small><strong>({key["d"]}, {key["n"]})</strong></div></div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">3</div><h2>Enkripsi</h2></div>',unsafe_allow_html=True)
if st.button("Enkripsi",use_container_width=True,disabled=not key_current):
    data=text_to_decimal_blocks(message,key["n"],3)
    cipher=encrypt_blocks(data["values"],key["e"],key["n"])
    st.session_state.cipher=cipher;st.session_state.cipher_chars=cipher_chars(cipher)
    st.session_state.lengths=data["lengths"];st.session_state.plain="";st.rerun()
if st.session_state.cipher:
    st.caption("Tampilan ciphertext")
    st.markdown(f'<div class="output">{html.escape(st.session_state.cipher_chars)}</div>',unsafe_allow_html=True)
    st.caption("Ciphertext angka")
    st.markdown(f'<div class="output">{" ".join(map(str,st.session_state.cipher))}</div>',unsafe_allow_html=True)
    st.download_button("Unduh ciphertext",json.dumps({"cipher":st.session_state.cipher,"lengths":st.session_state.lengths,"public_key":[key["e"],key["n"]]},indent=2),"ciphertext.json","application/json",use_container_width=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="card"><div class="card-head"><div class="step">4</div><h2>Dekripsi</h2></div>',unsafe_allow_html=True)
if st.button("Dekripsi",use_container_width=True,disabled=not key_current or not st.session_state.cipher):
    blocks=decrypt_blocks(st.session_state.cipher,key["d"],key["n"])
    st.session_state.plain,_,_=decimal_blocks_to_text(blocks,st.session_state.lengths);st.rerun()
if st.session_state.plain: st.markdown(f'<div class="output result">{html.escape(st.session_state.plain)}</div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)
st.markdown('<div class="footer">RSA demonstrasi · ciphertext angka digunakan untuk dekripsi</div>',unsafe_allow_html=True)
