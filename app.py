import json
from math import gcd
import streamlit as st
from src.rsa_math import (
    is_prime, valid_e_values, generate_key_data, text_to_decimal_blocks, decimal_blocks_to_text, encrypt_blocks, decrypt_blocks,
)

st.set_page_config(page_title="RSA PRIME LAB", page_icon="🔐", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
:root{--ink:#111;--paper:#fffdf4;--yellow:#ffd93d;--pink:#ff5d8f;--blue:#6c63ff;--cyan:#55e6c1;--red:#ff6b57;--shadow:6px 6px 0 #111}
[data-testid="stAppViewContainer"]{background:var(--paper);background-image:linear-gradient(#1111110a 1px,transparent 1px),linear-gradient(90deg,#1111110a 1px,transparent 1px);background-size:28px 28px}
[data-testid="stHeader"]{background:transparent}[data-testid="stSidebar"]{background:#ffe771;border-right:3px solid #111}
.block-container{max-width:1180px;padding-top:1.4rem;padding-bottom:5rem}h1,h2,h3{font-family:Arial Black,Impact,sans-serif!important;color:#111!important;letter-spacing:-.035em}h1{font-size:clamp(3rem,7vw,6.3rem)!important;line-height:.88!important;text-transform:uppercase;margin:.6rem 0 1rem!important}p,.stCaption{color:#292929}
.nb-hero{border:3px solid #111;background:#fff;padding:28px;box-shadow:10px 10px 0 #111;margin-bottom:24px;position:relative;overflow:hidden}.nb-tag{display:inline-block;border:2px solid #111;background:var(--pink);padding:7px 11px;font-weight:900;text-transform:uppercase;transform:rotate(-1deg)}.nb-lead{font-size:1.08rem;max-width:760px;line-height:1.65}.nb-warning{display:inline-block;background:var(--yellow);border:2px solid #111;padding:8px 12px;font-weight:800;margin-top:10px}
.roadmap{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}.road{border:3px solid #111;background:#fff;padding:14px;box-shadow:4px 4px 0 #111;font-size:.86rem}.road b{display:block;font-size:1rem;margin-bottom:4px}.road.active{background:var(--cyan)}
.section-head{display:flex;align-items:center;gap:14px;margin:3rem 0 1rem}.num{width:54px;height:54px;border:3px solid #111;background:var(--blue);color:#fff;display:grid;place-items:center;font-family:Arial Black;font-size:1.35rem;box-shadow:4px 4px 0 #111;transform:rotate(-2deg)}
.nb-card{border:3px solid #111;background:#fff;padding:18px;box-shadow:var(--shadow);height:100%}.nb-card.yellow{background:var(--yellow)}.nb-card.pink{background:#ffb3c9}.nb-card.cyan{background:#bff7e8}.nb-card.blue{background:#c8c5ff}.nb-card.red{background:#ffb0a4}.nb-label{font-family:Arial Black;text-transform:uppercase;font-size:.82rem;margin-bottom:8px}.formula{border:3px solid #111;background:#111;color:#fff;padding:18px;text-align:center;font-family:Georgia,serif;font-size:1.2rem;margin:12px 0}.key-card{border:3px solid #111;padding:16px;background:#fff;box-shadow:4px 4px 0 #111}.key-card.public{background:var(--cyan)}.key-card.private{background:#ffb3c9}.key-card strong{font-family:Arial Black;font-size:1.2rem}.big-value{font-family:Arial Black;font-size:clamp(1.6rem,4vw,3rem);overflow-wrap:anywhere}.status-ok{border:3px solid #111;background:var(--cyan);padding:13px;font-weight:850;box-shadow:4px 4px 0 #111}.status-bad{border:3px solid #111;background:#ffb0a4;padding:13px;font-weight:850;box-shadow:4px 4px 0 #111}.mini{font-size:.82rem;line-height:1.5}.footer-card{border:3px solid #111;background:#111;color:#fff;padding:22px;margin-top:3rem}.footer-card b{color:var(--yellow)}
.stButton>button,.stDownloadButton>button{border:3px solid #111!important;border-radius:0!important;box-shadow:4px 4px 0 #111!important;font-weight:900!important;text-transform:uppercase!important;min-height:3rem;background:#fff!important;color:#111!important}.stButton>button:hover,.stDownloadButton>button:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 #111!important}.stButton>button[kind="primary"]{background:var(--pink)!important}.stNumberInput input,.stTextInput input,.stTextArea textarea,.stSelectbox>div>div{border:3px solid #111!important;border-radius:0!important;background:#fff!important}.stTabs [data-baseweb="tab-list"]{gap:8px}.stTabs [data-baseweb="tab"]{border:3px solid #111;background:#fff;font-weight:900}.stTabs [aria-selected="true"]{background:var(--yellow)!important}.stDataFrame{border:3px solid #111}.stAlert{border:3px solid #111;border-radius:0}.stExpander{border:3px solid #111!important;border-radius:0!important;background:#fff}.sidebar-note{border:2px solid #111;background:#fff;padding:12px;box-shadow:3px 3px 0 #111;font-size:.82rem;margin:.6rem 0}
@media(max-width:800px){.roadmap{grid-template-columns:1fr 1fr}.block-container{padding-left:1rem;padding-right:1rem}.nb-hero{padding:19px;box-shadow:6px 6px 0 #111}}@media(max-width:480px){.roadmap{grid-template-columns:1fr}h1{font-size:3rem!important}}
</style>
""", unsafe_allow_html=True)

DEFAULTS={"key":None,"cipher":[],"plain_blocks":[],"block_lengths":[],"display_blocks":[],"ascii_codes":[],"digit_string":"","restored":"","number_cipher":None,"number_plain":None}
for k,v in DEFAULTS.items(): st.session_state.setdefault(k,v)

def reset_results():
    for key in DEFAULTS: st.session_state[key]=DEFAULTS[key]

def step_state(num):
    if num==1:return "active" if not st.session_state.key else ""
    if num==2:return "active" if st.session_state.key and not st.session_state.cipher else ""
    if num==3:return "active" if st.session_state.cipher and not st.session_state.restored else ""
    return "active" if st.session_state.restored else ""

with st.sidebar:
    st.markdown("## RSA PRIME LAB")
    st.markdown('<div class="sidebar-note"><b>TUJUAN</b><br>Pilih p dan q sendiri, lihat kunci terbentuk, lalu buktikan pesan kembali.</div>',unsafe_allow_html=True)
    st.markdown("### Cara pakai")
    st.markdown("**1.** Pilih dua bilangan prima berbeda")
    st.markdown("**2.** Pilih `e` yang relatif prima dengan φ(n)")
    st.markdown("**3.** Bangkitkan kunci")
    st.markdown("**4.** Enkripsi lalu dekripsi")
    st.markdown("**5.** Buka detail matematika")
    st.markdown('<div class="sidebar-note"><b>CATATAN</b><br>Ini textbook RSA untuk belajar, bukan sistem keamanan produksi.</div>',unsafe_allow_html=True)
    if st.button("Ulangi dari awal",use_container_width=True): reset_results(); st.rerun()

st.markdown('''<div class="nb-hero"><span class="nb-tag">Interactive discrete math</span><h1>Build RSA<br>from primes.</h1><p class="nb-lead">Pilih sendiri bilangan prima <b>p</b> dan <b>q</b>. Aplikasi menghitung <b>n</b>, <b>φ(n)</b>, kunci publik <b>(e,n)</b>, dan kunci privat <b>(d,n)</b>, lalu memperlihatkan enkripsi-dekripsi blok secara transparan.</p><span class="nb-warning">⚠ DEMO PENDIDIKAN - BILANGAN KECIL MUDAH DIFAKTORKAN</span></div>''',unsafe_allow_html=True)

roads=[("1","PILIH PRIMA","p dan q berbeda"),("2","BANGKITKAN KUNCI","n, φ, e, dan d"),("3","ENKRIPSI","c = mᵉ mod n"),("4","DEKRIPSI","m = cᵈ mod n")]
st.markdown('<div class="roadmap">'+''.join(f'<div class="road {step_state(i)}"><b>{n}. {t}</b>{d}</div>' for i,(n,t,d) in enumerate(roads,1))+'</div>',unsafe_allow_html=True)

st.markdown('<div class="section-head"><div class="num">01</div><div><h2>PILIH p DAN q</h2><p>Dua bilangan prima berbeda adalah fondasi pasangan kunci.</p></div></div>',unsafe_allow_html=True)
prime_options=[5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
input1,input2=st.columns(2,gap="large")
with input1:
    p=st.number_input("Bilangan prima p",min_value=2,step=1,value=None,placeholder="Masukkan p")
with input2:
    q=st.number_input("Bilangan prima q",min_value=2,step=1,value=None,placeholder="Masukkan q")
st.caption("Contoh bilangan prima: 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97")
p_valid=p is not None and is_prime(int(p))
q_valid=q is not None and is_prime(int(q))
if p is not None and not p_valid: st.error(f"p = {int(p)} bukan bilangan prima.")
if q is not None and not q_valid: st.error(f"q = {int(q)} bukan bilangan prima.")
if p_valid and q_valid and int(p)==int(q): st.error("p dan q harus berbeda.")
if not (p_valid and q_valid and int(p)!=int(q)):
    st.info("Masukkan p dan q yang prima dan berbeda.")
    st.stop()
p=int(p); q=int(q)

phi=(p-1)*(q-1); n=p*q
st.markdown('<div class="section-head"><div class="num">02</div><div><h2>BANGKITKAN KUNCI</h2><p>Hitung modulus, fungsi totien, lalu pilih eksponen publik.</p></div></div>',unsafe_allow_html=True)
a,b,c=st.columns(3)
with a: st.markdown(f'<div class="nb-card cyan"><div class="nb-label">MODULUS PUBLIK</div><div class="big-value">n = {n}</div><div class="mini">{p} × {q}</div></div>',unsafe_allow_html=True)
with b: st.markdown(f'<div class="nb-card yellow"><div class="nb-label">TOTIEN RAHASIA</div><div class="big-value">φ = {phi}</div><div class="mini">({p}-1)({q}-1)</div></div>',unsafe_allow_html=True)
with c:
    options=valid_e_values(phi)
    default=79 if 79 in options else (17 if 17 in options else options[0])
    e=st.selectbox("Pilih eksponen publik e",options,index=options.index(default),help="Hanya nilai dengan PBB(e, φ(n)) = 1 yang ditampilkan.")
    st.markdown(f'<div class="status-ok">PBB({e}, {phi}) = {gcd(e,phi)} ✓</div>',unsafe_allow_html=True)

if p==q:
    st.markdown('<div class="status-bad">p dan q harus berbeda sebelum kunci dapat dibuat.</div>',unsafe_allow_html=True)
elif st.button("BANGKITKAN PASANGAN KUNCI",type="primary",use_container_width=True):
    try:
        st.session_state.key=generate_key_data(p,q,e)
        st.session_state.cipher=[];st.session_state.restored="";st.session_state.number_cipher=None
        st.rerun()
    except ValueError as exc: st.error(str(exc))

key=st.session_state.key
if key:
    if (key["p"],key["q"],key["e"])!=(p,q,e):
        st.warning("Input berubah. Tekan Bangkitkan Pasangan Kunci untuk memperbarui hasil.")
    pub,priv=st.columns(2,gap="large")
    with pub: st.markdown(f'<div class="key-card public"><div class="nb-label">KUNCI PUBLIK - BOLEH DIBAGIKAN</div><strong>(e, n)</strong><div class="big-value">({key["e"]}, {key["n"]})</div><div class="mini">Digunakan untuk enkripsi.</div></div>',unsafe_allow_html=True)
    with priv: st.markdown(f'<div class="key-card private"><div class="nb-label">KUNCI PRIVAT - JANGAN DIBAGIKAN</div><strong>(d, n)</strong><div class="big-value">({key["d"]}, {key["n"]})</div><div class="mini">Karena {key["e"]} × {key["d"]} ≡ 1 (mod {key["phi"]}).</div></div>',unsafe_allow_html=True)
    with st.expander("Lihat perhitungan Euclidean dan balikan modulo"):
        st.write(f"Kita mencari d sehingga {key['e']}d ≡ 1 (mod {key['phi']}).")
        for dividend,quotient,divisor,remainder in key["euclid_steps"]:
            st.code(f"{dividend} = {quotient} × {divisor} + {remainder}")
        st.success(f"Balikan {key['e']} modulo {key['phi']} adalah d = {key['d']}.")

st.markdown('<div class="section-head"><div class="num">03</div><div><h2>ENKRIPSI PESAN</h2><p>Pilih mode angka untuk perhitungan tangan, atau mode teks untuk melihat pemecahan blok.</p></div></div>',unsafe_allow_html=True)
if not key:
    st.info("Bangkitkan pasangan kunci pada langkah 02 terlebih dahulu.")
else:
    tab_text,tab_number=st.tabs(["TEKS UTF-8","SATU BLOK ANGKA"])
    with tab_text:
        st.markdown('<div class="nb-card yellow"><b>METODE PPT:</b> karakter → ASCII desimal 2 digit → gabungkan → blok 3 digit → enkripsi.</div>',unsafe_allow_html=True)
        text=st.text_area("Pesan",value="HARI INI",height=110,help="Sesuai PPT: karakter harus memiliki kode kode 3 digit tetap 32-99.")
        st.caption("Didukung: spasi, tanda baca tertentu, angka, A-Z, dan a-c (ASCII 32-99).")
        if key["n"]<=999: st.warning(f"n={key['n']} mungkin terlalu kecil untuk blok 3 digit. Contoh PPT memakai n=3337.")
        if st.button("UBAH KE ASCII & ENKRIPSI",type="primary",use_container_width=True):
            try:
                x=text_to_decimal_blocks(text,key["n"],3)
                st.session_state.plain_blocks=x["values"];st.session_state.block_lengths=x["lengths"]
                st.session_state.display_blocks=x["display_blocks"];st.session_state.ascii_codes=x["ascii_codes"]
                st.session_state.digit_string=x["digit_string"];st.session_state.cipher=encrypt_blocks(x["values"],key["e"],key["n"]);st.session_state.restored=""
                st.rerun()
            except ValueError as exc: st.error(str(exc))
        if st.session_state.cipher:
            st.markdown("#### 1. Karakter → ASCII")
            st.dataframe([{"Karakter":"spasi" if ch==" " else ch,"ASCII":code} for ch,code in zip(text,st.session_state.ascii_codes)],use_container_width=True,hide_index=True)
            st.markdown("#### 2. Digit digabung")
            st.code(st.session_state.digit_string,language=None)
            st.markdown("#### 3. Blok 3 digit")
            st.code(" | ".join(st.session_state.display_blocks),language=None)
            rows=[{"Blok":i+1,"pᵢ":shown,"Rumus":f"{m}^{key['e']} mod {key['n']}","cᵢ":c} for i,(shown,m,c) in enumerate(zip(st.session_state.display_blocks,st.session_state.plain_blocks,st.session_state.cipher))]
            st.dataframe(rows,use_container_width=True,hide_index=True)
            st.markdown('<div class="formula">cᵢ = pᵢ<sup>e</sup> mod n</div>',unsafe_allow_html=True)
            st.code(" ".join(map(str,st.session_state.cipher)),language=None)
            st.download_button("UNDUH CIPHERTEXT JSON",json.dumps({"method":"PPT kode 3 digit tetap + blok 3 digit","ascii_codes":st.session_state.ascii_codes,"digits":st.session_state.digit_string,"plain_blocks":st.session_state.display_blocks,"cipher":st.session_state.cipher,"block_lengths":st.session_state.block_lengths,"public_key":[key["e"],key["n"]]},indent=2),"rsa_ciphertext.json","application/json",use_container_width=True)
    with tab_number:
        m=st.number_input("Plainteks angka m",min_value=0,max_value=key["n"]-1,value=min(9,key["n"]-1),step=1)
        st.caption(f"Syarat wajib: 0 ≤ m < n, jadi 0 ≤ m < {key['n']}.")
        if st.button("ENKRIPSI ANGKA",use_container_width=True):
            st.session_state.number_cipher=pow(int(m),key["e"],key["n"]);st.session_state.number_plain=None
        if st.session_state.number_cipher is not None:
            st.markdown(f'<div class="nb-card pink"><div class="nb-label">HASIL CIPHERTEXT</div><div class="big-value">c = {st.session_state.number_cipher}</div><div class="mini">{int(m)}<sup>{key["e"]}</sup> mod {key["n"]}</div></div>',unsafe_allow_html=True)

st.markdown('<div class="section-head"><div class="num">04</div><div><h2>DEKRIPSI & BUKTIKAN</h2><p>Pakai d untuk mengembalikan ciphertext ke plainteks awal.</p></div></div>',unsafe_allow_html=True)
if key and st.session_state.cipher:
    if st.button("DEKRIPSI TEKS DENGAN KUNCI PRIVAT",type="primary",use_container_width=True):
        try:
            recovered=decrypt_blocks(st.session_state.cipher,key["d"],key["n"])
            st.session_state.restored, st.session_state.recovered_blocks, st.session_state.recovered_codes = decimal_blocks_to_text(recovered,st.session_state.block_lengths)
            st.rerun()
        except (ValueError,UnicodeDecodeError) as exc: st.error(f"Dekripsi gagal: {exc}")
    if st.session_state.restored:
        st.markdown(f'<div class="status-ok"><div class="nb-label">ROUND TRIP BERHASIL ✓</div><div class="big-value">{st.session_state.restored}</div><div class="mini">Setiap blok dihitung dengan m = c<sup>{key["d"]}</sup> mod {key["n"]}.</div></div>',unsafe_allow_html=True)
elif key:
    st.info("Enkripsi teks pada langkah 03 agar tombol dekripsi tersedia.")
else:
    st.info("Bangkitkan pasangan kunci dan enkripsi pesan terlebih dahulu.")

if key and st.session_state.number_cipher is not None:
    st.markdown("### Dekripsi blok angka")
    if st.button("DEKRIPSI ANGKA",use_container_width=True):
        st.session_state.number_plain=pow(st.session_state.number_cipher,key["d"],key["n"])
    if st.session_state.number_plain is not None:
        st.markdown(f'<div class="nb-card cyan"><div class="big-value">m = {st.session_state.number_plain}</div><div class="mini">{st.session_state.number_cipher}<sup>{key["d"]}</sup> mod {key["n"]}</div></div>',unsafe_allow_html=True)

with st.expander("Mengapa demo ini tidak aman untuk data nyata?"):
    st.write("Aplikasi ini mengikuti metode PPT: ASCII desimal 2 digit, blok 3 digit, dan textbook RSA tanpa OAEP agar rumus kuliah terlihat langsung. Bilangan prima kecil mudah diuji dan n mudah difaktorkan. Sistem nyata memakai kunci besar, padding standar seperti OAEP, dan biasanya mengenkripsi kunci simetris, bukan pesan panjang langsung.")

st.markdown('''<div class="footer-card"><b>RINGKASAN</b><br>1) p,q prima → 2) n=pq dan φ=(p−1)(q−1) → 3) pilih e dengan PBB(e,φ)=1 → 4) d=e⁻¹ mod φ → 5) c=mᵉ mod n → 6) m=cᵈ mod n.</div>''',unsafe_allow_html=True)
