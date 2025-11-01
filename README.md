# 🔐 CodeSafe

**CodeSafe** is a lightweight, modular Python scanner designed to detect accidentally exposed secrets in your codebase — such as API keys, tokens, passwords, and other sensitive credentials.  

It combines **regex pattern matching**, **entropy-based detection**, and **.env-style key scanning** to ensure that sensitive data never slips into version control.

---

## 🧠 Features

- 🚀 **Three-layer detection**:  
  - Regex-based secret detection (`patterns.py`)  
  - Entropy-based random string detection (`entropy.py`)  
  - `.env`-style key scanning outside expected files (`env_keys.py`)
  
- 🧩 **Modular architecture** – easy to extend with new checks  
- 📂 **Recursive scanning** – automatically walks through all project files  
- 🧾 **Flexible outputs** – supports **JSON** and **SARIF** formats for GitHub integration  
- 🧹 **False-positive filtering** – ignores legitimate `.env` files  
- ⚡ **Lightweight CLI** – simple to run with one command

---

## 🗂️ Project Structure

