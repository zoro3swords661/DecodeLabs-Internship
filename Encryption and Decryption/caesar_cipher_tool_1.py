"""DecodeLabs Project 2 - Caesar Cipher Tool (Tkinter, stdlib only)."""

import tkinter as tk
from tkinter import messagebox

# --- Cipher engine ---
def caesar(text, shift):
    out = ""
    for c in text:
        if c.isupper():                          # base 65 for A-Z
            out += chr((ord(c) - 65 + shift) % 26 + 65)
        elif c.islower():                        # base 97 for a-z
            out += chr((ord(c) - 97 + shift) % 26 + 97)
        else:                                    # keep spaces/punctuation/digits
            out += c
    return out

encrypt = lambda t, n: caesar(t, n)              # E(x)=(x+n)%26
decrypt = lambda t, n: caesar(t, -n)             # D(x)=(x-n)%26

# --- Theme ---
BG, PANEL, ACCENT, ORANGE, TEXT, MUTED = "#0a1628", "#0f2038", "#2f9bff", "#ff7a33", "#e6eef7", "#7c93ac"
FONT = "Consolas"

class App:
    def __init__(self, root):
        self.root = root
        root.title("DecodeLabs | Caesar Cipher Tool")
        root.configure(bg=BG); root.geometry("760x640"); root.minsize(680, 600)
        self.shift = tk.IntVar(value=3)          # default key = 3
        self._build()

    def _panel(self, title):                     # titled card, returns its frame
        f = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground="#1d3a5c")
        f.pack(fill="x", padx=24, pady=8)
        tk.Label(f, text=title, font=(FONT, 10, "bold"), fg=ACCENT, bg=PANEL).pack(anchor="w", padx=14, pady=(10, 6))
        return f

    def _box(self, parent, fg, bg, locked=False):  # styled text box
        b = tk.Text(parent, height=5, font=(FONT, 12), bg=bg, fg=fg, wrap="word",
                    relief="flat", padx=10, pady=8, highlightthickness=1, highlightbackground=MUTED)
        b.pack(fill="x", padx=14, pady=(0, 12))
        if locked: b.config(state="disabled")
        return b

    def _btn(self, parent, label, colour, cmd):
        tk.Button(parent, text=label, command=cmd, font=(FONT, 11, "bold"), fg="#06121f",
                  bg=colour, relief="flat", padx=10, pady=10, cursor="hand2", bd=0
                  ).pack(side="left", expand=True, fill="x", padx=4)

    def _build(self):
        tk.Label(self.root, text="CAESAR CIPHER TOOL", font=(FONT, 22, "bold"), fg=TEXT, bg=BG).pack(anchor="w", padx=24, pady=(22, 0))
        tk.Label(self.root, text="Project 2 :: Confidentiality Logic :: DecodeLabs 2026", font=(FONT, 10), fg=ACCENT, bg=BG).pack(anchor="w", padx=24)

        # INPUT + key slider
        p = self._panel("INPUT // Plaintext")
        self.inp = self._box(p, TEXT, PANEL)
        self.inp.insert("1.0", "Hello, World!")
        row = tk.Frame(p, bg=PANEL); row.pack(fill="x", padx=14, pady=(0, 12))
        tk.Label(row, text="KEY (shift n):", font=(FONT, 10, "bold"), fg=MUTED, bg=PANEL).pack(side="left")
        tk.Scale(row, from_=1, to=25, orient="horizontal", variable=self.shift, length=300, command=self._on_slide,
                 bg=PANEL, fg=ACCENT, troughcolor=BG, highlightthickness=0, font=(FONT, 9)).pack(side="left", padx=12)

        # Buttons
        b = tk.Frame(self.root, bg=BG); b.pack(fill="x", padx=20, pady=10)
        self._btn(b, " ENCRYPT", ACCENT, self.do_encrypt)
        self._btn(b, " DECRYPT", ORANGE, self.do_decrypt)
        self._btn(b, "↺ CLEAR", MUTED, self.do_clear)

        # OUTPUT + validation
        self.out = self._box(self._panel("OUTPUT // Result"), ACCENT, BG, locked=True)
        self.val = self._box(self._panel("VALIDATION // Decrypt-back check"), MUTED, PANEL, locked=True)
        tk.Label(self.root, text="Symmetric encryption: the same key locks and unlocks.",
                 font=(FONT, 9), fg=MUTED, bg=BG).pack(pady=10)

    def _write(self, box, content):             # write into a locked box
        box.config(state="normal"); box.delete("1.0", "end")
        box.insert("1.0", content); box.config(state="disabled")

    def _on_slide(self, _):                     # re-encrypt live when key changes
        if self.out.get("1.0", "end-1c").strip(): self.do_encrypt()

    def do_encrypt(self):
        text = self.inp.get("1.0", "end-1c")
        if not text.strip(): return messagebox.showwarning("Empty", "Type some text to encrypt.")
        n = self.shift.get(); cipher = encrypt(text, n)
        self._write(self.out, cipher)
        ok = "MATCH ✓" if decrypt(cipher, n) == text else "MISMATCH ✗"
        self._write(self.val, f"decrypt(ciphertext, key={n}) -> {decrypt(cipher, n)}\noriginal == recovered ? {ok}")

    def do_decrypt(self):
        text = self.inp.get("1.0", "end-1c")
        if not text.strip(): return messagebox.showwarning("Empty", "Paste ciphertext to decrypt.")
        n = self.shift.get()
        self._write(self.out, decrypt(text, n))
        self._write(self.val, f"Applied D(x)=(x-{n})%26 to the input box.")

    def do_clear(self):
        self.inp.delete("1.0", "end"); self._write(self.out, ""); self._write(self.val, "")

if __name__ == "__main__":
    root = tk.Tk(); App(root); root.mainloop()
