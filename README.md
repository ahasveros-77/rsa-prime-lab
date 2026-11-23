# RSA Prime Lab

Interactive educational Streamlit app for building textbook RSA from user-selected prime values `p` and `q`.

## Features
- Select distinct prime values `p` and `q`
- Calculate `n = pq` and `phi(n) = (p-1)(q-1)`
- Select a valid public exponent `e`
- Calculate private exponent `d` with Extended Euclidean Algorithm
- Encrypt/decrypt numbers and UTF-8 text blocks
- Inspect every modular arithmetic step
- Download ciphertext as JSON
- Responsive neo-brutalist Streamlit interface

> Educational only. This demonstrates textbook RSA without OAEP and small primes. Do not use it for real secrets.

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`.

## Deploy on Streamlit Community Cloud
1. Push this directory to a GitHub repository.
2. Sign in to Streamlit Community Cloud.
3. Create a new app and select the repository.
4. Set the main file path to `app.py`.
5. Deploy. No secrets or external backend are required.

## Suggested Git commands
```bash
git init
git add .
git commit -m "Initial commit: RSA Prime Lab"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/rsa-prime-lab.git
git push -u origin main
```

## Structure
```text
rsa-prime-lab/
├── .streamlit/config.toml
├── src/__init__.py
├── src/rsa_math.py
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```
