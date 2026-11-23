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
.header{border-bottom:2px solid var(--ink);padding-bottom:1.2rem;margin-bottom:1.8rem}.section{border:2px solid var(--ink);background:var(--card);padding:1rem;margin:1rem 0}.section-title{display:flex;align-items:center;gap:.6rem;margin-bottom:1rem}.step{width:28px;height:28px;display:grid;place-items:center;background:var(--accent);border:2px solid var(--ink);font-weight:900}.keys{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-top:1rem}.key{border:2px solid var(--ink);padding:.8rem;background:#f8f8f8}.key small{display:block;color:var(--muted);font-weight:800;text-transform:uppercase}.key strong{display:block;margin-top:.2rem;overflow-wrap:anywhere}.output{border:2px solid var(--ink);background:#fafafa;padding:.8rem;font-family:ui-monospace,monospace;overflow-wrap:anywhere}.success{background:var(--accent)}
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
with p_col: p=st.number_input("Bilangan prima p",min_value=2,step=1,value=None,placeholder="Masukkan p")
with q_col: q=st.number_input("Bilangan prima q",min_value=2,step=1,value=None,placeholder="Masukkan q")
st.caption("Contoh prima: 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97")

p_ok=p is not None and is_prime(int(p)); q_ok=q is not None and is_prime(int(q))
if p is not None and not p_ok: st.error(f"{int(p)} bukan bilangan prima.")
if q is not None and not q_ok: st.error(f"{int(q)} bukan bilangan prima.")
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
if st.button("Enkripsi",use_container_width=True,disabled=not key or not message):
    try:
        data=text_to_decimal_blocks(message,key["n"],3)
        c=encrypt_blocks(data["values"],key["e"],key["n"])
        st.session_state.cipher=c;st.session_state.cipher_chars=cipher_chars(c)
        st.session_state.lengths=data["lengths"];st.session_state.details=data;st.session_state.plain="";st.rerun()
    except ValueError as exc: st.error(str(exc))

if st.session_state.cipher:
    st.caption("Ciphertext karakter")
    st.markdown(f'<div class="output">{st.session_state.cipher_chars}</div>',unsafe_allow_html=True)
    st.caption("Ciphertext angka")
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

st.markdown('<div class="footer">Textbook RSA. Jangan gunakan untuk data sensitif.</div>',unsafe_allow_html=True)
