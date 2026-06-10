# 🔐 Caesar Cipher Tool

**DecodeLabs Industrial Training Kit — Cybersecurity Project 2 (Batch 2026)**
*Basic Encryption & Decryption*

A simple desktop application that encrypts and decrypts text using the
**Caesar cipher**. Built in Python with a Tkinter graphical interface and
themed to match the DecodeLabs "blueprint" style. It demonstrates the core
ideas of **data confidentiality**: turning readable plaintext into
unreadable ciphertext and reversing the process with the same key.

---

## ✨ Features

- **Encrypt** any text using a Caesar shift cipher.
- **Decrypt** ciphertext back to the original plaintext.
- **Choose your own key** with a slider (shift values 1–25).
- **Live preview** — drag the slider after encrypting and the ciphertext updates instantly.
- **Built-in validation** — the app decrypts its own output and confirms it matches the original.
- **Edge-case safe** — spaces, punctuation, and digits pass through unchanged.
- **Zero dependencies** — uses only Python's standard library (Tkinter).

---

## 🎯 Requirements Met (from the project brief)

| Requirement | Status | Where in the app |
|---|---|---|
| Encrypt user text with basic logic (Caesar cipher) | ✅ | `ENCRYPT` button → `caesar()` engine |
| Decrypt the encrypted text | ✅ | `DECRYPT` button → reverse shift |
| Display both encrypted and decrypted output | ✅ | OUTPUT panel + VALIDATION panel |
| Implement the IPO cycle | ✅ | INPUT → PROCESS → OUTPUT layout |
| Apply the math: `ord()`, `chr()`, `% 26` | ✅ | Inside `caesar()` |
| Handle edge cases (spaces / punctuation) | ✅ | `else: out += c` branch |
| Validate with a decryption function | ✅ | Auto decrypt-back check |

---

## 🧠 How It Works (the math)

Each letter is shifted by a key `n` using its ASCII number:

```
Encrypt:  E(x) = (x + n) % 26
Decrypt:  D(x) = (x - n) % 26
```

Example with key = 3 (the classic Caesar shift):

```
'A' → ord → 65 → (65 - 65 + 3) % 26 + 65 → 68 → chr → 'D'
'Y' → ord → 89 → (89 - 65 + 3) % 26 + 65 → 66 → chr → 'B'   (wraps around)
```

The `% 26` keeps the result inside the 26-letter alphabet, so `Z` wraps
back to `A`.

---

## 🗂 Project Structure

```
caesar_cipher_tool.py   # the entire application (engine + UI)
README.md               # this file
REPORT.md               # detailed technical report
```

The program is split into three clear parts:

1. **Cipher engine** — pure logic (`caesar`, `encrypt`, `decrypt`).
2. **Theme constants** — colours and font.
3. **`App` class** — the Tkinter window and all button actions.

---

## ▶️ How to Run

You need **Python 3** installed. Tkinter comes bundled with Python, so there
is nothing to `pip install`.

```bash
python caesar_cipher_tool.py
```

(On some systems use `python3` instead of `python`.)

---

## 📖 Usage Guide

1. Type or paste your text into the **INPUT** box.
2. Set the **KEY** slider to your chosen shift value.
3. Click **🔒 ENCRYPT** to see the ciphertext in the OUTPUT box.
4. Click **🔓 DECRYPT** to turn ciphertext back into readable text.
5. Click **↺ CLEAR** to reset all boxes.

> Tip: After encrypting once, drag the KEY slider to watch the ciphertext
> change live.

---

## ⚠️ Security Note

The Caesar cipher is for **learning only**, not real security. With just 25
possible keys it can be brute-forced instantly, and it preserves letter
frequency patterns. Real systems use algorithms like **AES** with large keys.
This project is the foundational first step toward understanding them.

---

## 🚀 Future Enhancements

- Brute-force panel showing all 25 possible decryptions.
- Vigenère cipher (a stronger, keyword-based cipher).
- Save / load encrypted text to a file.

---

## 👤 Author

Cybersecurity Intern — DecodeLabs Batch 2026
*Replace this line with your name before submitting.*
