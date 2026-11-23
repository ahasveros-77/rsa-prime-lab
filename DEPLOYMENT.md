# Deployment Guide

## GitHub
```bash
git init
git add .
git commit -m "Initial commit: RSA Prime Lab"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/rsa-prime-lab.git
git push -u origin main
```

## Streamlit Community Cloud
- Repository: your `rsa-prime-lab` repository
- Branch: `main`
- Main file path: `app.py`
- Python dependencies: automatically installed from `requirements.txt`
- Secrets: none required

After deployment, use **Manage app > Reboot app** if a new commit does not appear immediately.
