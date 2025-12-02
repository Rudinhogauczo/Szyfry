import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import datetime

def caesar_cipher(text, key, decrypt=False):
    result = ""
    if decrypt:
        key = -key
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + key) % 26 + base)
        else:
            result += char
    return result

def vigenere_cipher(text, key, decrypt=False):
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % len(key)]) - ord('a')
            if decrypt:
                k = -k
            result += chr((ord(char) - base + k) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def running_key_cipher(text, key, decrypt=False):
    result = ""
    key = key.lower()
    ki = 0
    for i, char in enumerate(text):
        if char.isalpha():
            is_upper = char.isupper()
            p = ord(char.lower()) - ord('a')
            k = ord(key[ki]) - ord('a')
            c = (p + k) % 26 if not decrypt else (p - k) % 26
            ch = chr(c + ord('a'))
            result += ch.upper() if is_upper else ch
            ki += 1
        else:
            result += char
    return result

def aes_encrypt(text, key, mode="CBC", decrypt=False):

    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    elif isinstance(key, bytes):
        key_bytes = key
    else:
        raise ValueError("Nieprawidłowy typ klucza AES (wymagany str lub bytes).")

    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Klucz AES musi mieć 16, 24 lub 32 bajty.")

    if decrypt:
        data = base64.b64decode(text)
        if mode in ("CBC", "CTR"):
            iv_or_nonce = data[:16]
            ciphertext = data[16:]
        else:
            iv_or_nonce = b''
            ciphertext = data
    else:
        data = text.encode('utf-8')
        if mode in ("ECB", "CBC"):
            padder = sym_padding.PKCS7(128).padder()
            data = padder.update(data) + padder.finalize()
            iv_or_nonce = os.urandom(16) if mode == "CBC" else b''
        elif mode == "CTR":
            iv_or_nonce = os.urandom(16)
        ciphertext = data

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_or_nonce), backend=default_backend())
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_or_nonce), backend=default_backend())
    else:
        raise ValueError("Nieznany tryb AES")

    if decrypt:
        decryptor = cipher.decryptor()
        result_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        if mode in ("ECB", "CBC"):
            unpadder = sym_padding.PKCS7(128).unpadder()
            result_bytes = unpadder.update(result_bytes) + unpadder.finalize()
        return result_bytes.decode('utf-8')
    else:
        encryptor = cipher.encryptor()
        result_bytes = encryptor.update(ciphertext) + encryptor.finalize()
        return base64.b64encode(iv_or_nonce + result_bytes).decode('utf-8')

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    encrypted = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt(text, private_key):
    encrypted_bytes = base64.b64decode(text)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode('utf-8')

def generate_ec_keys(curve=ec.SECP384R1()):
    priv = ec.generate_private_key(curve, backend=default_backend())
    pub = priv.public_key()
    return priv, pub

def ec_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def ec_private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_ec_private(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

def load_ec_public(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())

def derive_shared_key(private_key, peer_public_key, length=32):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'ecdh derived key',
        backend=default_backend()
    )
    key = hkdf.derive(shared_secret)
    return key

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikacja szyfrująca (z ECDH)")
        self.root.geometry("1080x1080")

        ttk.Label(root, text="Aplikacja szyfrująca", font=("Arial", 18, "bold")).pack(pady=10)

        self.algorithms_map = {"Cezar": caesar_cipher, "Vigenère": vigenere_cipher,
                               "Running Key": running_key_cipher, "AES": aes_encrypt, "RSA": None, "ECDH": None}

        self.rsa_private_key = None
        self.rsa_public_key = None

        self.ec_private_key = None
        self.ec_public_key = None
        self.ec_peer_public_key = None
        self.ec_shared_key = None 

        ttk.Label(root, text="Wybierz algorytm:").pack()
        self.algorithm_var = tk.StringVar(value="Cezar")
        alg_box = ttk.Combobox(root, textvariable=self.algorithm_var,
                               values=list(self.algorithms_map.keys()), state="readonly")
        alg_box.pack(pady=5)
        alg_box.bind("<<ComboboxSelected>>", self.update_key_hint)

        self.key_label = ttk.Label(root, text="Podaj klucz (liczba całkowita):")
        self.key_label.pack(pady=5)

        vcmd = (root.register(self.validate_key_input), "%P")
        self.key_entry = ttk.Entry(root, validate="key", validatecommand=vcmd, width=40)
        self.key_entry.insert(0, "3")
        self.key_entry.pack(pady=5)

        self.aes_mode_var = tk.StringVar(value="CBC")
        self.aes_mode_box = ttk.Combobox(root, textvariable=self.aes_mode_var,
                                         values=["ECB", "CBC", "CTR"], state="readonly")

        ttk.Label(root, text="Tekst do zaszyfrowania / odszyfrowania:").pack()
        self.text_input = tk.Text(root, height=6)
        self.text_input.pack(fill="x", padx=10, pady=5)

        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="Szyfruj tekst", command=self.encrypt_text).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Odszyfruj tekst", command=self.decrypt_text).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Szyfruj plik", command=self.encrypt_file).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Odszyfruj plik", command=self.decrypt_file).grid(row=1, column=1, padx=5, pady=5)

        rsa_frame = ttk.Frame(root)
        rsa_frame.pack(pady=6)
        ttk.Button(rsa_frame, text="Generuj klucze RSA", command=self.generate_and_set_rsa_keys).grid(row=0, column=0, padx=5)
        ttk.Button(rsa_frame, text="Zapisz klucze RSA", command=self.save_rsa_keys).grid(row=0, column=1, padx=5)
        ttk.Button(rsa_frame, text="Wczytaj klucze RSA", command=self.load_rsa_keys).grid(row=0, column=2, padx=5)

        ecdh_frame = ttk.LabelFrame(root, text="ECDH (Diffie-Hellman na krzywych eliptycznych)")
        ecdh_frame.pack(fill="x", padx=10, pady=6)
        ttk.Button(ecdh_frame, text="Generuj klucze ECDH", command=self.generate_and_set_ec_keys).grid(row=0, column=0, padx=5, pady=4)
        ttk.Button(ecdh_frame, text="Zapisz klucze ECDH", command=self.save_ec_keys).grid(row=0, column=1, padx=5, pady=4)
        ttk.Button(ecdh_frame, text="Wczytaj klucze ECDH", command=self.load_ec_keys).grid(row=0, column=2, padx=5, pady=4)
        ttk.Button(ecdh_frame, text="Zapisz klucz publiczny (do udostępnienia)", command=self.export_public_ec).grid(row=1, column=0, padx=5, pady=4)
        ttk.Button(ecdh_frame, text="Wczytaj klucz publiczny partnera", command=self.import_peer_public_ec).grid(row=1, column=1, padx=5, pady=4)
        ttk.Button(ecdh_frame, text="Wyprowadź wspólny sekret (HKDF)", command=self.derive_shared_secret_action).grid(row=1, column=2, padx=5, pady=4)
        ttk.Label(ecdh_frame, text="Uwaga: wynikowy sekret (32 bajty) będzie użyty jako klucz AES przy algorytmie ECDH").grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=4)

        ttk.Label(root, text="Wynik:").pack()
        self.result_box = tk.Text(root, height=7)
        self.result_box.pack(fill="x", padx=10, pady=5)

        self.hint_label = ttk.Label(root, text="➡ Klucz musi być liczbą całkowitą dla Cezara.", foreground="gray")
        self.hint_label.pack(pady=5)

        ttk.Label(root, text="Logi operacji:").pack(pady=5)
        self.log_box = ScrolledText(root, height=10, state="disabled", foreground="blue")
        self.log_box.pack(fill="both", padx=10, pady=5, expand=True)
        self.logs = []

        self.update_key_hint()

    def add_log(self, algorithm, operation, status, info=""):
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{time_str}] {algorithm} | {operation} | {status} | {info}"
        self.logs.append(log_entry)
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, log_entry + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")

    def update_key_hint(self, event=None):
        alg = self.algorithm_var.get()
        try:
            self.aes_mode_box.pack_forget()
        except Exception:
            pass
        if alg == "Cezar":
            self.key_label.config(text="Podaj klucz (liczba całkowita):")
            self.hint_label.config(text="➡ Klucz musi być liczbą całkowitą.")
            self.key_entry.config(validate="key")
        elif alg == "Vigenère":
            self.key_label.config(text="Podaj klucz (słowo):")
            self.hint_label.config(text="➡ Klucz to słowo (tylko litery).")
            self.key_entry.config(validate="none")
        elif alg == "Running Key":
            self.key_label.config(text="Podaj klucz (długi tekst):")
            self.hint_label.config(text="➡ Klucz musi być co najmniej tak długi jak tekst.")
            self.key_entry.config(validate="none")
        elif alg == "AES":
            self.key_label.config(text="Podaj klucz (16, 24 lub 32 znaki):")
            self.hint_label.config(text="➡ Klucz musi mieć 16, 24 lub 32 znaki. Wybierz tryb AES.")
            self.aes_mode_box.pack(pady=5)
            self.key_entry.config(validate="none")
        elif alg == "RSA":
            self.key_label.config(text="Klucze RSA będą generowane automatycznie")
            self.hint_label.config(text="➡ Możesz wygenerować klucze, zapisać je lub wczytać z pliku.")
            self.key_entry.delete(0, tk.END)
            self.key_entry.config(validate="none")
        elif alg == "ECDH":
            self.key_label.config(text="ECDH: użyj przycisków aby wygenerować/wczytać klucze i wyprowadzić sekret")
            self.hint_label.config(text="➡ Po wyprowadzeniu sekretu (HKDF) możesz szyfrować/odszyfrowywać używając ECDH (sekret jako klucz AES).")
            self.key_entry.delete(0, tk.END)
            self.key_entry.config(validate="none")
            self.aes_mode_box.pack(pady=5)

    def validate_key_input(self, new_value):
        alg = self.algorithm_var.get()
        if alg == "Cezar":
            return new_value.isdigit() or new_value == ""
        return True

    def generate_and_set_rsa_keys(self):
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keys()
        messagebox.showinfo("Sukces", "Para kluczy RSA została wygenerowana.")
        self.add_log("RSA", "Generacja kluczy", "Sukces")

    def save_rsa_keys(self):
        if self.rsa_private_key is None or self.rsa_public_key is None:
            messagebox.showwarning("Uwaga", "Klucze RSA nie zostały wygenerowane.")
            return
        priv_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz prywatny")
        if not priv_path: return
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz publiczny")
        if not pub_path: return

        priv_bytes = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(priv_path, "wb") as f:
            f.write(priv_bytes)
        pub_bytes = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(pub_path, "wb") as f:
            f.write(pub_bytes)
        messagebox.showinfo("Sukces", "Klucze RSA zapisane pomyślnie.")
        self.add_log("RSA", "Zapis kluczy", "Sukces")

    def load_rsa_keys(self):
        priv_path = filedialog.askopenfilename(title="Wybierz klucz prywatny", filetypes=[("PEM files", "*.pem")])
        if not priv_path: return
        pub_path = filedialog.askopenfilename(title="Wybierz klucz publiczny", filetypes=[("PEM files", "*.pem")])
        if not pub_path: return
        with open(priv_path, "rb") as f:
            self.rsa_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(pub_path, "rb") as f:
            self.rsa_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        messagebox.showinfo("Sukces", "Klucze RSA wczytane pomyślnie.")
        self.add_log("RSA", "Wczytanie kluczy", "Sukces")

    def generate_and_set_ec_keys(self):
        try:
            self.ec_private_key, self.ec_public_key = generate_ec_keys()
            messagebox.showinfo("Sukces", "Para kluczy ECDH została wygenerowana.")
            self.add_log("ECDH", "Generacja kluczy", "Sukces")
        except Exception as e:
            self.add_log("ECDH", "Generacja kluczy", "Błąd", str(e))
            messagebox.showerror("Błąd", f"Generowanie kluczy ECDH nie powiodło się: {e}")

    def save_ec_keys(self):
        if self.ec_private_key is None or self.ec_public_key is None:
            messagebox.showwarning("Uwaga", "Klucze ECDH nie zostały wygenerowane.")
            return
        priv_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz prywatny ECDH")
        if not priv_path: return
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz publiczny ECDH")
        if not pub_path: return

        with open(priv_path, "wb") as f:
            f.write(ec_private_bytes(self.ec_private_key))
        with open(pub_path, "wb") as f:
            f.write(ec_public_bytes(self.ec_public_key))

        messagebox.showinfo("Sukces", "Klucze ECDH zapisane pomyślnie.")
        self.add_log("ECDH", "Zapis kluczy", "Sukces")

    def load_ec_keys(self):
        priv_path = filedialog.askopenfilename(title="Wybierz klucz prywatny ECDH", filetypes=[("PEM files", "*.pem")])
        if not priv_path: return
        pub_path = filedialog.askopenfilename(title="Wybierz klucz publiczny ECDH", filetypes=[("PEM files", "*.pem")])
        if not pub_path: return
        try:
            with open(priv_path, "rb") as f:
                self.ec_private_key = load_ec_private(f.read())
            with open(pub_path, "rb") as f:
                self.ec_public_key = load_ec_public(f.read())
            messagebox.showinfo("Sukces", "Klucze ECDH wczytane pomyślnie.")
            self.add_log("ECDH", "Wczytanie kluczy", "Sukces")
        except Exception as e:
            self.add_log("ECDH", "Wczytanie kluczy", "Błąd", str(e))
            messagebox.showerror("Błąd", f"Wczytanie kluczy ECDH nie powiodło się: {e}")

    def export_public_ec(self):
        if self.ec_public_key is None:
            messagebox.showwarning("Uwaga", "Klucz publiczny ECDH nie istnieje. Wygeneruj lub wczytaj klucze.")
            return
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz publiczny (PEM)")
        if not pub_path: return
        with open(pub_path, "wb") as f:
            f.write(ec_public_bytes(self.ec_public_key))
        messagebox.showinfo("Sukces", "Klucz publiczny zapisany do pliku.")
        self.add_log("ECDH", "Eksport klucza publicznego", "Sukces")

    def import_peer_public_ec(self):
        pub_path = filedialog.askopenfilename(title="Wczytaj klucz publiczny partnera (PEM)", filetypes=[("PEM files", "*.pem")])
        if not pub_path: return
        try:
            with open(pub_path, "rb") as f:
                self.ec_peer_public_key = load_ec_public(f.read())
            messagebox.showinfo("Sukces", "Klucz publiczny partnera wczytany.")
            self.add_log("ECDH", "Import klucza partnera", "Sukces")
        except Exception as e:
            self.add_log("ECDH", "Import klucza partnera", "Błąd", str(e))
            messagebox.showerror("Błąd", f"Wczytanie klucza publicznego partnera nie powiodło się: {e}")

    def derive_shared_secret_action(self):
        if self.ec_private_key is None:
            messagebox.showwarning("Uwaga", "Brak klucza prywatnego ECDH. Wygeneruj lub wczytaj klucze.")
            return
        if self.ec_peer_public_key is None:
            messagebox.showwarning("Uwaga", "Brak klucza publicznego partnera. Wczytaj klucz partnera.")
            return
        try:
            self.ec_shared_key = derive_shared_key(self.ec_private_key, self.ec_peer_public_key, length=32)
            b64 = base64.b64encode(self.ec_shared_key).decode('utf-8')
            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, f"Wspólny sekret (Base64, 32 bajty):\n{b64}")
            self.add_log("ECDH", "Derivacja sekretu", "Sukces", f"Sekret: {len(self.ec_shared_key)} bajtów")
            messagebox.showinfo("Sukces", "Wspólny sekret wyprowadzony. Możesz użyć algorytmu ECDH do AES.")
        except Exception as e:
            self.ec_shared_key = None
            self.add_log("ECDH", "Derivacja sekretu", "Błąd", str(e))
            messagebox.showerror("Błąd", f"Derivacja sekretu nie powiodła się: {e}")

    def process_text(self, decrypt=False):
        alg_name = self.algorithm_var.get()
        algorithm = self.algorithms_map.get(alg_name)
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        operation = "Odszyfrowanie" if decrypt else "Szyfrowanie"

        try:
            if alg_name == "Cezar":
                key = int(key)
            if alg_name in ["Vigenère", "Running Key"]:
                if not key.isalpha():
                    raise ValueError("Klucz musi zawierać tylko litery.")
            if alg_name == "AES":
                if len(key.encode('utf-8')) not in (16,24,32):
                    raise ValueError("Klucz AES musi mieć 16, 24 lub 32 bajty.")    

            if alg_name == "RSA":
                if self.rsa_private_key is None or self.rsa_public_key is None:
                    raise ValueError("Klucze RSA nie zostały wygenerowane.")
                result = rsa_decrypt(text, self.rsa_private_key) if decrypt else rsa_encrypt(text, self.rsa_public_key)

            elif alg_name == "ECDH":
                if self.ec_shared_key is None:
                    raise ValueError("Wspólny sekret ECDH nie został wyprowadzony. Wygeneruj/cload klucze i zaimportuj klucz partnera.")
                mode = self.aes_mode_var.get()

                result = aes_encrypt(text, self.ec_shared_key, mode=mode, decrypt=decrypt)

            elif alg_name == "AES":
                mode = self.aes_mode_var.get()
                result = aes_encrypt(text, key, mode=mode, decrypt=decrypt)

            else:
                result = algorithm(text, key, decrypt=decrypt)

            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, result)
            self.add_log(alg_name, operation, "Sukces", f"{len(text)} znaków")

        except Exception as e:
            self.add_log(alg_name, operation, "Błąd", str(e))
            messagebox.showerror("Błąd", f"Wystąpił problem: {e}")

    def encrypt_text(self): self.process_text(decrypt=False)
    def decrypt_text(self): self.process_text(decrypt=True)

    def process_file(self, decrypt=False):
        file_path = filedialog.askopenfilename(title="Wybierz plik")
        if not file_path: return
        alg_name = self.algorithm_var.get()
        algorithm = self.algorithms_map.get(alg_name)
        key = self.key_entry.get().strip()
        operation = "Odszyfrowanie pliku" if decrypt else "Szyfrowanie pliku"
        try:
            with open(file_path, "r", encoding="utf-8") as f: data = f.read()

            if alg_name == "Cezar": key = int(key)
            if alg_name in ["Vigenère","Running Key"] and not key.isalpha(): raise ValueError("Klucz musi zawierać tylko litery.")
            if alg_name=="AES" and len(key.encode('utf-8')) not in (16,24,32): raise ValueError("Klucz AES musi mieć długość 16,24 lub 32 znaków")

            if alg_name == "RSA":
                if self.rsa_private_key is None or self.rsa_public_key is None:
                    raise ValueError("Klucze RSA nie zostały wygenerowane.")
                result = rsa_decrypt(data, self.rsa_private_key) if decrypt else rsa_encrypt(data, self.rsa_public_key)

            elif alg_name == "ECDH":
                if self.ec_shared_key is None:
                    raise ValueError("Wspólny sekret ECDH nie został wyprowadzony.")
                mode = self.aes_mode_var.get()
                result = aes_encrypt(data, self.ec_shared_key, mode=mode, decrypt=decrypt)

            elif alg_name=="AES":
                mode = self.aes_mode_var.get()
                result = aes_encrypt(data, key, mode=mode, decrypt=decrypt)

            else:
                result = algorithm(data, key, decrypt=decrypt)

            save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Zapisz wynik")
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(result)
                messagebox.showinfo("Sukces", "Operacja zakończona pomyślnie.")
                self.add_log(alg_name, operation, "Sukces", f"Plik: {os.path.basename(file_path)}")
        except Exception as e:
            self.add_log(alg_name, operation, "Błąd", str(e))
            messagebox.showerror("Błąd", str(e))

    def encrypt_file(self): self.process_file(decrypt=False)
    def decrypt_file(self): self.process_file(decrypt=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
