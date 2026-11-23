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
)

st.set_page_config(page_title="Enkripsi RSA", page_icon="🔐", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
:root{--ink:#171717;--paper:#f7f6f2;--white:#fff;--accent:#dcff45;--blue:#dff4ff;--pink:#ffe1e2;--muted:#68665f}
[data-testid="stAppViewContainer"]{background:var(--paper)}[data-testid="stHeader"]{background:transparent}[data-testid="stSidebar"]{display:none}
.block-container{max-width:980px;padding:2rem 1.2rem 4rem}h1,h2{color:var(--ink)!important;letter-spacing:-.04em}h1{font-size:clamp(2.7rem,7vw,4.6rem)!important;line-height:1!important;margin:0!important}h2{font-size:1.35rem!important;margin:0!important}p,.stCaption{color:var(--muted)}
.topbar{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--ink);padding-bottom:1rem;margin-bottom:2.5rem}.brand{font-weight:900}.tag{border:2px solid var(--ink);background:var(--accent);padding:.35rem .6rem;font-size:.7rem;font-weight:850;text-transform:uppercase}.hero{margin-bottom:2.7rem}.hero p{max-width:590px;margin:.8rem 0 0}.section{display:flex;align-items:center;gap:.7rem;margin:2.8rem 0 1rem}.num{width:32px;height:32px;display:grid;place-items:center;border:2px solid var(--ink);background:var(--accent);box-shadow:3px 3px 0 var(--ink);font-weight:900}
.metric,.key{border:2px solid var(--ink);background:#fff;padding:1rem;height:100%}.metric-label{font-size:.7rem;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.metric-value{font-size:clamp(1.55rem,4vw,2.35rem);font-weight:900;letter-spacing:-.045em;overflow-wrap:anywhere}.key.public{background:var(--blue)}.key.private{background:var(--pink)}.key strong{display:block;font-size:1.3rem;margin-top:.25rem;overflow-wrap:anywhere}.result{border:2px solid var(--ink);background:var(--accent);box-shadow:4px 4px 0 var(--ink);padding:1rem;margin-top:1rem}.result strong{display:block;font-size:1.25rem;margin-top:.2rem;overflow-wrap:anywhere}.cipher-preview{border:2px solid var(--ink);background:#fff;padding:1rem;font-family:ui-monospace,monospace;font-size:1.2rem;overflow-wrap:anywhere;min-height:58px}
.stButton>button,.stDownloadButton>button{border:2px solid var(--ink)!important;border-radius:0!important;min-height:2.8rem;background:#fff!important;color:var(--ink)!important;font-weight:850!important;box-shadow:3px 3px 0 var(--ink)!important}.stButton>button[kind="primary"]{background:var(--accent)!important}.stButton>button:hover,.stDownloadButton>button:hover{transform:translate(1px,1px);box-shadow:2px 2px 0 var(--ink)!important}.stNumberInput input,.stTextArea textarea{border:2px solid var(--ink)!important;border-radius:0!important;background:#fff!important}.stTabs [data-baseweb="tab-list"]{gap:.45rem}.stTabs [data-baseweb="tab"]{border:2px solid var(--ink);background:#fff;font-weight:800}.stTabs [aria-selected="true"]{background:var(--accent)!important}.stExpander{border:2px solid var(--ink)!important;border-radius:0!important;background:#fff}.stAlert{border:2px solid var(--ink);border-radius:0}.footer{border-top:2px solid var(--ink);margin-top:3rem;padding-top:1rem;color:var(--muted);font-size:.78rem}@media(max-width:640px){.block-container{padding-top:1rem}.tag{display:none}.topbar{margin-bottom:1.8rem}}
</style>
""", unsafe_allow_html=True)

DEFAULTS={"key":None,"cipher":[],"plain_blocks":[],"block_lengths":[],"display_blocks":[],"ascii_codes":[],"digit_string":"","cipher_chars":"","restored":"","number_cipher":None,"number_plain":None}
for name,value in DEFAULTS.items(): st.session_state.setdefault(name,value)

def clear_results():
    for name,value in DEFAULTS.items():
        if name!="key": st.session_state[name]=value

def cipher_as_characters(values):
    # The RSA results can exceed ASCII 127. Unicode code points keep this preview reversible.
    return "".join(chr(value) if 0 <= value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF else "�" for value in values)

st.markdown('<div class="topbar"><div class="brand">RSA LAB</div><div class="tag">Textbook RSA</div></div>',unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>Enkripsi RSA</h1><p>Masukkan dua bilangan prima, buat kunci, lalu enkripsi dan dekripsi pesan.</p></div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="num">1</div><h2>Buat kunci</h2></div>',unsafe_allow_html=True)
p_col,q_col=st.columns(2,gap="large")
with p_col: p=st.number_input("Bilangan prima p",min_value=2,step=1,value=None,placeholder="Contoh: 47")
with q_col: q=st.number_input("Bilangan prima q",min_value=2,step=1,value=None,placeholder="Contoh: 71")

p_valid=p is not None and is_prime(int(p))
q_valid=q is not None and is_prime(int(q))
distinct=p is not None and q is not None and int(p)!=int(q)
if p is not None and not p_valid: st.error(f"p = {int(p)} bukan bilangan prima.")
if q is not None and not q_valid: st.error(f"q = {int(q)} bukan bilangan prima.")
if p_valid and q_valid and not distinct: st.error("p dan q harus berbeda.")

inputs_valid=p_valid and q_valid and distinct
if inputs_valid:
    p_int,q_int=int(p),int(q); n=p_int*q_int; phi=(p_int-1)*(q_int-1)
    m1,m2,m3=st.columns(3,gap="medium")
    with m1: st.markdown(f'<div class="metric"><div class="metric-label">n = p × q</div><div class="metric-value">{n}</div></div>',unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric"><div class="metric-label">φ(n)</div><div class="metric-value">{phi}</div></div>',unsafe_allow_html=True)
    with m3:
        e=st.number_input("Eksponen publik e",min_value=2,max_value=max(2,phi-1),step=1,value=None,placeholder="Contoh: 79")
        e_valid=e is not None and 1<int(e)<phi and gcd(int(e),phi)==1
        if e is not None and not e_valid: st.error(f"e harus relatif prima terhadap φ(n) = {phi}.")
    if st.button("Buat pasangan kunci",type="primary",use_container_width=True,disabled=not e_valid):
        st.session_state.key=generate_key_data(p_int,q_int,int(e)); clear_results(); st.rerun()
else:
    e=None
    st.info("Masukkan p dan q yang prima dan berbeda.")

key=st.session_state.key
if key:
    if not inputs_valid or (key["p"],key["q"])!=(int(p),int(q)):
        st.warning("Nilai p atau q berubah. Buat ulang pasangan kunci untuk memakai nilai baru.")
    k1,k2=st.columns(2,gap="large")
    with k1: st.markdown(f'<div class="key public"><div class="metric-label">Kunci publik</div><strong>({key["e"]}, {key["n"]})</strong></div>',unsafe_allow_html=True)
    with k2: st.markdown(f'<div class="key private"><div class="metric-label">Kunci privat</div><strong>({key["d"]}, {key["n"]})</strong></div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="num">2</div><h2>Enkripsi</h2></div>',unsafe_allow_html=True)
if not key:
    st.info("Buat pasangan kunci terlebih dahulu.")
else:
    text_tab,number_tab=st.tabs(["Pesan teks","Angka"])
    with text_tab:
        message=st.text_area("Pesan",height=100,placeholder="Masukkan pesan")
        if st.button("Enkripsi pesan",type="primary",use_container_width=True,disabled=not message):
            try:
                converted=text_to_decimal_blocks(message,key["n"],3)
                cipher=encrypt_blocks(converted["values"],key["e"],key["n"])
                st.session_state.plain_blocks=converted["values"]; st.session_state.block_lengths=converted["lengths"]
                st.session_state.display_blocks=converted["display_blocks"]; st.session_state.ascii_codes=converted["ascii_codes"]
                st.session_state.digit_string=converted["digit_string"]; st.session_state.cipher=cipher
                st.session_state.cipher_chars=cipher_as_characters(cipher); st.session_state.restored=""; st.rerun()
            except ValueError as exc: st.error(str(exc))
        if st.session_state.cipher:
            st.text_area("Ciphertext angka"," ".join(map(str,st.session_state.cipher)),height=80,disabled=True)
            st.markdown('<div class="metric-label">Teks terenkripsi</div>',unsafe_allow_html=True)
            st.markdown(f'<div class="cipher-preview">{st.session_state.cipher_chars}</div>',unsafe_allow_html=True)
            st.caption("Nilai cipher dapat melebihi ASCII 127, jadi tampilan karakter memakai Unicode code point. Dekripsi tetap menggunakan ciphertext angka agar hasil tepat.")
            with st.expander("Detail perhitungan"):
                st.dataframe([{"Karakter":"spasi" if ch==" " else ch,"ASCII":code} for ch,code in zip(message,st.session_state.ascii_codes)],use_container_width=True,hide_index=True)
                st.caption("Gabungan digit"); st.code(st.session_state.digit_string,language=None)
                st.caption("Blok tiga digit"); st.code(" | ".join(st.session_state.display_blocks),language=None)
            st.download_button("Unduh ciphertext",json.dumps({"cipher":st.session_state.cipher,"cipher_chars":st.session_state.cipher_chars,"block_lengths":st.session_state.block_lengths,"public_key":[key["e"],key["n"]]},ensure_ascii=False,indent=2),"rsa_ciphertext.json","application/json",use_container_width=True)
    with number_tab:
        number=st.number_input("Nilai plainteks m",min_value=0,max_value=key["n"]-1,step=1,value=None,placeholder=f"0 sampai {key['n']-1}")
        if st.button("Enkripsi angka",use_container_width=True,disabled=number is None):
            st.session_state.number_cipher=pow(int(number),key["e"],key["n"]); st.session_state.number_plain=None
        if st.session_state.number_cipher is not None: st.markdown(f'<div class="result"><div class="metric-label">Ciphertext</div><strong>{st.session_state.number_cipher}</strong></div>',unsafe_allow_html=True)

st.markdown('<div class="section"><div class="num">3</div><h2>Dekripsi</h2></div>',unsafe_allow_html=True)
if key and st.session_state.cipher:
    if st.button("Dekripsi pesan",type="primary",use_container_width=True):
        try:
            recovered=decrypt_blocks(st.session_state.cipher,key["d"],key["n"])
            st.session_state.restored,_,_=decimal_blocks_to_text(recovered,st.session_state.block_lengths); st.rerun()
        except (ValueError,UnicodeDecodeError) as exc: st.error(f"Dekripsi gagal: {exc}")
    if st.session_state.restored: st.markdown(f'<div class="result"><div class="metric-label">Hasil dekripsi</div><strong>{st.session_state.restored}</strong></div>',unsafe_allow_html=True)
elif key: st.info("Enkripsi pesan untuk melanjutkan.")
else: st.info("Buat pasangan kunci untuk melanjutkan.")

if key and st.session_state.number_cipher is not None:
    if st.button("Dekripsi angka",use_container_width=True): st.session_state.number_plain=pow(st.session_state.number_cipher,key["d"],key["n"])
    if st.session_state.number_plain is not None: st.markdown(f'<div class="result"><div class="metric-label">Plainteks</div><strong>{st.session_state.number_plain}</strong></div>',unsafe_allow_html=True)

st.markdown('<div class="footer">Textbook RSA untuk pembelajaran. Jangan gunakan untuk data rahasia.</div>',unsafe_allow_html=True)
