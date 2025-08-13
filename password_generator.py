#!/usr/bin/env python3
"""
Password Generator GUI (Tkinter)
- Crypto-secure randomness (secrets)
- Options: length, lowercase/uppercase/digits/symbols
- Exclude ambiguous characters (O,0,l,1,I,|)
- Guarantees at least one char from each selected set
- Strength meter (entropy) + label
- Generate multiple passwords, copy, save history, export
"""

import math
import string
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ------------- Config -------------

SYMBOLS = "!@#$%^&*-=+_?~"  # friendly symbols
AMBIGUOUS = set("O0oIl1|`'\";:,.{}[]()<>")  # remove when 'exclude ambiguous' is on
MAX_HISTORY = 50

# ------------- Helpers -------------

def build_charset(use_lower, use_upper, use_digits, use_symbols, exclude_ambiguous):
    """Return (list_of_selected_sets, merged_pool_string)."""
    sets = []
    if use_lower:  sets.append(string.ascii_lowercase)
    if use_upper:  sets.append(string.ascii_uppercase)
    if use_digits: sets.append(string.digits)
    if use_symbols:sets.append(SYMBOLS)
    if not sets:
        raise ValueError("Select at least one character set.")

    pool = "".join(sets)
    if exclude_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
        if not pool:
            raise ValueError("All characters were excluded. Relax options.")
        # Also filter each set for consistency
        filtered = []
        for s in sets:
            s2 = "".join(ch for ch in s if ch not in AMBIGUOUS)
            if s2:
                filtered.append(s2)
        sets = filtered
        if not sets:
            raise ValueError("No usable characters remain after exclusions.")
    return sets, pool

def crypto_randbelow(n: int) -> int:
    """Return a secure random int in [0, n)."""
    # secrets.randbelow is already crypto-secure:
    return secrets.randbelow(n)

def choice(pool: str) -> str:
    return pool[crypto_randbelow(len(pool))]

def generate_one(length: int, selected_sets: list[str], pool: str) -> str:
    """Guarantee one char from each selected set, fill rest, then shuffle."""
    if length < len(selected_sets):
        raise ValueError(f"Length must be at least {len(selected_sets)} to include one of each selected type.")

    pwd = [choice(s) for s in selected_sets]  # guarantee step
    # fill remaining
    for _ in range(length - len(pwd)):
        pwd.append(choice(pool))
    # Fisher–Yates shuffle
    for i in range(len(pwd) - 1, 0, -1):
        j = crypto_randbelow(i + 1)
        pwd[i], pwd[j] = pwd[j], pwd[i]
    return "".join(pwd)

def bits_entropy(length: int, pool_size: int) -> float:
    if pool_size < 2:
        return 0.0
    return round(length * math.log2(pool_size), 2)

def strength_label(b: float) -> str:
    if b < 40:  return "Weak"
    if b < 60:  return "Reasonable"
    if b < 80:  return "Strong"
    return "Very strong"

# ------------- GUI App -------------

class PasswordApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Password Generator")
        self.resizable(False, False)
        self.configure(padx=14, pady=14)

        # State
        self.history: list[str] = []

        # --- Controls frame ---
        frm = ttk.LabelFrame(self, text="Options")
        frm.grid(row=0, column=0, sticky="ew", padx=2, pady=(0,8))

        # Length
        self.len_var = tk.IntVar(value=16)
        ttk.Label(frm, text="Length:").grid(row=0, column=0, sticky="w", padx=(8,6), pady=8)
        self.len_scale = ttk.Scale(frm, from_=6, to=64, orient="horizontal",
                                   command=self._on_len_slide)
        self.len_scale.set(self.len_var.get())
        self.len_scale.grid(row=0, column=1, sticky="ew", padx=(0,8), pady=8)
        frm.columnconfigure(1, weight=1)
        self.len_label = ttk.Label(frm, text="16")
        self.len_label.grid(row=0, column=2, sticky="e", padx=(0,8), pady=8)

        # Checkboxes
        self.lower_var  = tk.BooleanVar(value=True)
        self.upper_var  = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var= tk.BooleanVar(value=True)
        self.excl_var   = tk.BooleanVar(value=False)

        row = 1
        ttk.Checkbutton(frm, text="Lowercase (a–z)", variable=self.lower_var, command=self.update_entropy
                        ).grid(row=row, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(frm, text="Uppercase (A–Z)", variable=self.upper_var, command=self.update_entropy
                        ).grid(row=row, column=1, sticky="w", padx=8, pady=2)
        row += 1
        ttk.Checkbutton(frm, text="Digits (0–9)", variable=self.digits_var, command=self.update_entropy
                        ).grid(row=row, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(frm, text=f"Symbols ({SYMBOLS})", variable=self.symbols_var, command=self.update_entropy
                        ).grid(row=row, column=1, sticky="w", padx=8, pady=2)
        row += 1
        ttk.Checkbutton(frm, text="Exclude ambiguous (O,0,l,1,I,|)", variable=self.excl_var, command=self.update_entropy
                        ).grid(row=row, column=0, columnspan=3, sticky="w", padx=8, pady=2)

        # Count
        row += 1
        ttk.Label(frm, text="How many passwords?").grid(row=row, column=0, sticky="w", padx=8, pady=(8,2))
        self.count_var = tk.IntVar(value=3)
        self.count_spin = ttk.Spinbox(frm, from_=1, to=20, textvariable=self.count_var, width=6)
        self.count_spin.grid(row=row, column=1, sticky="w", padx=8, pady=(8,2))

        # Entropy meter
        row += 1
        meter_frame = ttk.Frame(frm)
        meter_frame.grid(row=row, column=0, columnspan=3, sticky="ew", padx=8, pady=(8,6))
        meter_frame.columnconfigure(0, weight=1)
        self.entropy_label = ttk.Label(meter_frame, text="Entropy: —")
        self.entropy_label.grid(row=0, column=0, sticky="w")
        self.entropy_bar = ttk.Progressbar(meter_frame, mode="determinate", maximum=100, value=0)
        self.entropy_bar.grid(row=1, column=0, sticky="ew", pady=(4,0))
        self.strength_lbl = ttk.Label(meter_frame, text="")
        self.strength_lbl.grid(row=1, column=1, sticky="w", padx=(8,0))

        # Action buttons
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="ew", padx=8, pady=(8,8))
        ttk.Button(btns, text="Generate", command=self.generate).grid(row=0, column=0, padx=(0,6))
        ttk.Button(btns, text="Clear Output", command=self.clear_output).grid(row=0, column=1, padx=(0,6))
        ttk.Button(btns, text="Export History", command=self.export_history).grid(row=0, column=2)

        # --- Output frame ---
        out_frame = ttk.LabelFrame(self, text="Generated Passwords")
        out_frame.grid(row=1, column=0, sticky="ew", padx=2, pady=(0,8))
        self.out_container = ttk.Frame(out_frame)
        self.out_container.grid(row=0, column=0, sticky="ew")
        out_frame.columnconfigure(0, weight=1)

        # --- History frame ---
        hist_frame = ttk.LabelFrame(self, text="History (last 50)")
        hist_frame.grid(row=2, column=0, sticky="ew", padx=2)
        self.hist_container = ttk.Frame(hist_frame)
        self.hist_container.grid(row=0, column=0, sticky="ew")
        hist_frame.columnconfigure(0, weight=1)

        # Initial entropy
        self.update_entropy()

        # Native theming (ttk)
        try:
            self.style = ttk.Style(self)
            if "vista" in self.style.theme_names():
                self.style.theme_use("vista")
        except Exception:
            pass

    # ---- UI callbacks ----

    def _on_len_slide(self, _):
        val = int(self.len_scale.get())
        self.len_var.set(val)
        self.len_label.config(text=str(val))
        self.update_entropy()

    def update_entropy(self):
        try:
            sets, pool = build_charset(
                self.lower_var.get(), self.upper_var.get(),
                self.digits_var.get(), self.symbols_var.get(),
                self.excl_var.get()
            )
            b = bits_entropy(self.len_var.get(), len(pool))
            lbl = strength_label(b)
            self.entropy_label.config(text=f"Entropy: {b} bits")
            self.strength_lbl.config(text=lbl)
            # Map bits (0..100+) to 0..100 bar
            pct = 95 if b >= 80 else 75 if b >= 60 else 50 if b >= 40 else 25 if b > 0 else 0
            self.entropy_bar['value'] = pct
        except Exception:
            self.entropy_label.config(text="Entropy: —")
            self.strength_lbl.config(text="")
            self.entropy_bar['value'] = 0

    def clear_output(self):
        for w in self.out_container.winfo_children():
            w.destroy()

    def render_password_row(self, pw: str, parent: tk.Widget):
        row = ttk.Frame(parent)
        row.pack(fill="x", padx=8, pady=4)

        ent = ttk.Entry(row)
        ent.insert(0, pw)
        ent.config(width=48)
        ent.pack(side="left", padx=(0,6))

        def do_copy():
            self.clipboard_clear()
            self.clipboard_append(ent.get())
            self.update()  # keep in clipboard
            messagebox.showinfo("Copied", "Password copied to clipboard.")

        ttk.Button(row, text="Copy", command=do_copy).pack(side="left", padx=(0,6))

        def save_to_history():
            self.history.append(ent.get())
            if len(self.history) > MAX_HISTORY:
                self.history = self.history[-MAX_HISTORY:]
            self.render_history()
            messagebox.showinfo("Saved", "Added to history.")

        ttk.Button(row, text="Save", command=save_to_history).pack(side="left")

    def render_history(self):
        for w in self.hist_container.winfo_children():
            w.destroy()
        if not self.history:
            ttk.Label(self.hist_container, text="(empty)").pack(anchor="w", padx=8, pady=6)
            return
        for pw in reversed(self.history):
            r = ttk.Frame(self.hist_container)
            r.pack(fill="x", padx=8, pady=3)
            e = ttk.Entry(r)
            e.insert(0, pw)
            e.config(width=48)
            e.pack(side="left", padx=(0,6))
            def make_copy(txt=e.get()):
                self.clipboard_clear()
                self.clipboard_append(txt)
                self.update()
            ttk.Button(r, text="Copy", command=make_copy).pack(side="left", padx=(0,6))
            def delete_one(txt=pw, frame=r):
                try:
                    self.history.remove(txt)
                except ValueError:
                    pass
                frame.destroy()
            ttk.Button(r, text="Delete", command=delete_one).pack(side="left")

    def export_history(self):
        if not self.history:
            messagebox.showinfo("Export", "History is empty.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for pw in self.history:
                    f.write(pw + "\n")
            messagebox.showinfo("Export", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def generate(self):
        # Clear output area
        self.clear_output()

        try:
            count = int(self.count_var.get())
            if count < 1 or count > 20:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid input", "Count must be between 1 and 20.")
            return

        try:
            selected_sets, pool = build_charset(
                self.lower_var.get(), self.upper_var.get(),
                self.digits_var.get(), self.symbols_var.get(),
                self.excl_var.get()
            )
        except ValueError as e:
            messagebox.showerror("Options error", str(e))
            return

        length = int(self.len_var.get())

        try:
            for _ in range(count):
                pw = generate_one(length, selected_sets, pool)
                self.render_password_row(pw, self.out_container)
            # refresh entropy label
            self.update_entropy()
        except ValueError as e:
            messagebox.showerror("Generation error", str(e))

# ------------- Main -------------

if __name__ == "__main__":
    app = PasswordApp()
    app.mainloop()
