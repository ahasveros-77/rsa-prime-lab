import json
from math import gcd
import streamlit as st
from src.rsa_math import (
    is_prime, valid_e_values, generate_key_data,
    text_to_decimal_blocks, decimal_blocks_to_text,
    encrypt_blocks, decrypt_blocks,
)

st.set_page_config(page_title="RSA Encryptor", page_icon="🔐", layout="centered")

st.markdown("""
<style>
:root{--ink:#171717;--paper:#f7f7f4;--card:#fff;--accent:#dfff52;--muted:#686868}
[data-testid="stAppViewContainer"]{background:var(--paper)}
[data-testid="stHeader"]{background:transparent}
.block-container{max-width:760px;padding:2rem 1rem 4rem}
h1{font-size:2.4rem!important;letter-spacing:-.05em;margin:0 0 .35rem!important;color:var(--ink)!important}
h2{font-size:1.15rem!important;letter-spacing:-.02em;color:var(--ink)!important;margin:0!important}
p,.stCaption{color:var(--muted)}
.header{border-bottom:2px solid var(--ink);padding-bottom:1.2rem;margin-bottom:1.8rem}.section{border:2px solid var(--ink);background:var(--card);padding:1rem;margin:1rem 0}.section-title{display:flex;align-items:center;gap:.6rem;margin-bottom:1rem}.step{width:28px;height:28px;display:grid;place-items:center;background:var(--accent);border:2px solid var(--ink);font-weight:900}.keys{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-top:1rem}.key{border:2px solid var(--ink);padding:.8rem;background:#f8f8f8}.key small{display:block;color:var(--muted);font-weight:800;text-transform:uppercase}.key strong{display:block;margin-top:.2rem;overflow-wrap:anywhere}.output{border:2px solid var(--ink);background:#fafafa;padding:.8rem;font-family:ui-monospace,monospace;overflow-wrap:anywhere}.success{background:var(--accent)}.compat{border:2px solid var(--ink);padding:.75rem .85rem;margin:.65rem 0;font-size:.86rem}.compat.ok{background:#e5f8ed}.compat.bad{background:#ffe2e2}.hint{display:flex;gap:.45rem;flex-wrap:wrap;margin:.45rem 0 .8rem}.hint span{border:1.5px solid var(--ink);padding:.22rem .42rem;background:#fff;font-size:.72rem;font-weight:750}.subtle{font-size:.78rem;color:var(--muted);margin-top:.35rem}
.stButton>button,.stDownloadButton>button{border:2px solid var(--ink)!important;border-radius:0!important;background:var(--accent)!important;color:var(--ink)!important;font-weight:800!important;min-height:2.7rem}.stNumberInput input,.stTextArea textarea,.stSelectbox>div>div{border:2px solid var(--ink)!important;border-radius:0!important;background:#fff!important}.stAlert{border:2px solid var(--ink);border-radius:0}.stExpander{border:2px solid var(--ink)!important;border-radius:0!important;background:#fff}.footer{font-size:.75rem;color:var(--muted);margin-top:1.5rem}@media(max-width:560px){.keys{grid-template-columns:1fr}}
</style>
""",unsafe_allow_html=True)

for key,value in {
    "rsa_key":None,"cipher":[],"cipher_chars":"","lengths":[],"details":None,"plain":""
}.items(): st.session_state.setdefault(key,value)

def cipher_chars(values):
    return "".join(chr(v) if 0 <= v <= 0x10FFFF and not 0xD800 <= v <= 0xDFFF else "�" for v in values)

st.markdown('<div class="header"><h1>Enkripsi RSA</h1><p>Enkripsi dan dekripsi pesan dengan pasangan kunci RSA.</p></div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="section-title"><div class="step">1</div><h2>Kunci RSA</h2></div>',unsafe_allow_html=True)
p_col,q_col=st.columns(2)
with p_col: p=st.number_input("Bilangan prima p",min_value=2,max_value=10000,step=1,value=None,placeholder="2-10.000")
with q_col: q=st.number_input("Bilangan prima q",min_value=2,max_value=10000,step=1,value=None,placeholder="2-10.000")
st.caption("Rentang input: 2-10.000. Contoh prima:")
st.markdown('<div class="hint"><span>11</span><span>47</span><span>71</span><span>101</span><span>251</span><span>499</span><span>997</span><span>1.009</span><span>2.003</span><span>5.003</span><span>7.001</span><span>9.973</span></div>',unsafe_allow_html=True)

p_ok=p is not None and is_prime(int(p)); q_ok=q is not None and is_prime(int(q))
if p is not None and not p_ok: st.error(f"p = {int(p)} bukan bilangan prima. Pilih salah satu contoh di bawah input.")
if q is not None and not q_ok: st.error(f"q = {int(q)} bukan bilangan prima. Pilih salah satu contoh di bawah input.")
valid_primes=p_ok and q_ok and int(p)!=int(q)
if p_ok and q_ok and int(p)==int(q): st.error("p dan q harus berbeda.")

if valid_primes:
    p_i,q_i=int(p),int(q); phi=(p_i-1)*(q_i-1)
    options=valid_e_values(phi)
    e=st.selectbox("Eksponen publik e",options)
    st.caption(f"n = {p_i*q_i} · φ(n) = {phi} · PBB(e, φ) = {gcd(e,phi)}")
    if st.button("Buat kunci",use_container_width=True):
        st.session_state.rsa_key=generate_key_data(p_i,q_i,e)
        st.session_state.cipher=[];st.session_state.plain="";st.rerun()

key=st.session_state.rsa_key
if key:
    st.markdown(f'<div class="keys"><div class="key"><small>Publik</small><strong>({key["e"]}, {key["n"]})</strong></div><div class="key"><small>Privat</small><strong>({key["d"]}, {key["n"]})</strong></div></div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="section-title"><div class="step">2</div><h2>Enkripsi</h2></div>',unsafe_allow_html=True)
message=st.text_area("Pesan",height=100,placeholder="Tulis pesan")
message_codes=[ord(ch) for ch in message] if message else []
max_code=max(message_codes,default=0)
key_current=bool(key) and (p is not None and q is not None and int(p)==key["p"] and int(q)==key["q"])
compatible=key_current and bool(message) and max_code < key["n"] and max_code <= 999

if message and key_current:
    if max_code > 999:
        st.markdown(f'<div class="compat bad"><b>Karakter tidak didukung.</b><br>Kode terbesar {max_code}; format 3 digit hanya mendukung 000-999.</div>',unsafe_allow_html=True)
    elif max_code >= key["n"]:
        st.markdown(f'<div class="compat bad"><b>Modulus terlalu kecil.</b><br>Pesan membutuhkan n &gt; {max_code}, sedangkan kunci ini memiliki n = {key["n"]}. Pilih p dan q lebih besar, lalu buat kunci ulang.</div>',unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="compat ok"><b>Kunci kompatibel.</b> n = {key["n"]} lebih besar dari kode karakter maksimum {max_code}.</div>',unsafe_allow_html=True)
elif key and not key_current:
    st.warning("Nilai p atau q berubah. Buat kunci ulang sebelum mengenkripsi.")

if st.button("Enkripsi",use_container_width=True,disabled=not compatible):
    try:
        data=text_to_decimal_blocks(message,key["n"],3)
        c=encrypt_blocks(data["values"],key["e"],key["n"])
        st.session_state.cipher=c;st.session_state.cipher_chars=cipher_chars(c)
        st.session_state.lengths=data["lengths"];st.session_state.details=data;st.session_state.plain="";st.rerun()
    except ValueError as exc: st.error(str(exc))

if st.session_state.cipher:
    st.caption("Tampilan ciphertext")
    st.markdown(f'<div class="output">{st.session_state.cipher_chars}</div>',unsafe_allow_html=True)
    st.caption("Ciphertext RSA (data utama)")
    st.markdown(f'<div class="output">{" ".join(map(str,st.session_state.cipher))}</div>',unsafe_allow_html=True)
    with st.expander("Detail"):
        st.write("Kode 3 digit:", " ".join(st.session_state.details["ascii_codes"]))
    st.download_button("Unduh ciphertext",json.dumps({"cipher":st.session_state.cipher,"lengths":st.session_state.lengths},indent=2),"ciphertext.json","application/json",use_container_width=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="section-title"><div class="step">3</div><h2>Dekripsi</h2></div>',unsafe_allow_html=True)
if st.button("Dekripsi",use_container_width=True,disabled=not key or not st.session_state.cipher):
    try:
        blocks=decrypt_blocks(st.session_state.cipher,key["d"],key["n"])
        st.session_state.plain,_,_=decimal_blocks_to_text(blocks,st.session_state.lengths);st.rerun()
    except ValueError as exc: st.error(str(exc))
if st.session_state.plain:
    st.markdown(f'<div class="output success">{st.session_state.plain}</div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)

st.markdown('<div class="footer">RSA demonstrasi. Ciphertext angka digunakan untuk dekripsi.</div>',unsafe_allow_html=True)
