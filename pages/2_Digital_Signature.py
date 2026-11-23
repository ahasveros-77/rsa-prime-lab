import html,json
import streamlit as st
from src.rsa_signature import generate_signature_keys,sign_message,verify_signature
st.set_page_config(page_title="Digital Signature",page_icon="✍️",layout="centered")
st.markdown("""<style>:root{--i:#121212;--p:#f4f1e8;--a:#dfff4f;--b:#76d7ff;--r:#ff8fb3}[data-testid=stAppViewContainer]{background:var(--p)}.block-container{max-width:820px;padding:2rem 1rem}h1{font-size:3.5rem!important;letter-spacing:-.05em}.hero,.card{border:3px solid var(--i);background:#fff;box-shadow:7px 7px 0 var(--i);padding:1.2rem;margin:1.2rem 0}.head{font-weight:900;font-size:1.2rem;border-bottom:2px solid var(--i);padding-bottom:.7rem;margin-bottom:1rem}.keys{display:grid;grid-template-columns:1fr 1fr;gap:.7rem}.key,.out{border:2px solid var(--i);padding:.8rem;overflow-wrap:anywhere}.pub{background:var(--b)}.priv{background:var(--r)}.ok{background:var(--a);font-weight:900}.bad{background:#ffe0e0;font-weight:900}.stButton>button,.stDownloadButton>button{border:3px solid var(--i)!important;border-radius:0!important;background:var(--a)!important;color:var(--i)!important;font-weight:900!important;box-shadow:4px 4px 0 var(--i)!important}.stTextArea textarea,.stSelectbox>div>div{border:3px solid var(--i)!important;border-radius:0!important}@media(max-width:600px){.keys{grid-template-columns:1fr}}</style>""",unsafe_allow_html=True)
for k,v in {"sk":None,"sig":None,"signed":"","hash":"","vr":None}.items():st.session_state.setdefault(k,v)
st.markdown('<div class="hero"><h1>Digital Signature</h1></div>',unsafe_allow_html=True)
st.markdown('<div class="card"><div class="head">1 · Kunci RSA</div>',unsafe_allow_html=True)
bits=st.selectbox("Ukuran prima",[130,192,256],format_func=lambda x:f"{x} bit")
if st.button("Buat pasangan kunci",use_container_width=True):
    with st.spinner("Membuat bilangan prima..."):st.session_state.sk=generate_signature_keys(bits);st.session_state.sig=None;st.session_state.vr=None;st.rerun()
k=st.session_state.sk
if k:
    st.caption(f"Modulus {k['n'].bit_length()} bit · e = {k['e']}")
    st.markdown(f'<div class="keys"><div class="key pub"><b>Publik</b><br>({k["e"]}, {k["n"]})</div><div class="key priv"><b>Privat</b><br>({k["d"]}, {k["n"]})</div></div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)
st.markdown('<div class="card"><div class="head">2 · Buat signature</div>',unsafe_allow_html=True)
m=st.text_area("Pesan",height=100,key="sm")
if st.button("Tandatangani",use_container_width=True,disabled=not k or not m):
    r=sign_message(m,k["d"],k["n"]);st.session_state.sig=r["signature"];st.session_state.hash=r["hash"];st.session_state.signed=m;st.session_state.vr=None;st.rerun()
if st.session_state.sig is not None:
    st.caption("SHA-256");st.markdown(f'<div class="out">{st.session_state.hash}</div>',unsafe_allow_html=True)
    st.caption("Signature");st.markdown(f'<div class="out">{st.session_state.sig}</div>',unsafe_allow_html=True)
    st.download_button("Unduh signature",json.dumps({"signature":str(st.session_state.sig),"public_key":{"e":k["e"],"n":str(k["n"])}},indent=2),"signature.json","application/json",use_container_width=True)
st.markdown('</div>',unsafe_allow_html=True)
st.markdown('<div class="card"><div class="head">3 · Verifikasi</div>',unsafe_allow_html=True)
v=st.text_area("Pesan untuk diverifikasi",value=st.session_state.signed,height=100,key="vm")
if st.button("Verifikasi",use_container_width=True,disabled=not k or st.session_state.sig is None or not v):st.session_state.vr=verify_signature(v,st.session_state.sig,k["e"],k["n"]);st.rerun()
if st.session_state.vr is not None:
    valid=st.session_state.vr["valid"];st.markdown(f'<div class="out {"ok" if valid else "bad"}">{"Signature valid" if valid else "Signature tidak valid"}</div>',unsafe_allow_html=True)
st.markdown('</div>',unsafe_allow_html=True)
