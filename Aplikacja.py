import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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
    text = text.lower()
    key = key.lower()
    if len(key) < len(text):
        raise ValueError("Klucz musi być co najmniej tak długi jak tekst!")
    for i, char in enumerate(text):
        if char.isalpha():
            p = ord(char) - ord('a')
            k = ord(key[i]) - ord('a')
            c = (p + k) % 26 if not decrypt else (p - k) % 26
            result += chr(c + ord('a'))
        else:
            result += char
    return result



def aes_encrypt(text, key, mode="CBC", decrypt=False):
    key_bytes = key.encode('utf-8')
    if decrypt:
        data = base64.b64decode(text)
        if mode in ["CBC", "CTR"]:
            iv_or_nonce = data[:16]
            ciphertext = data[16:]
        else:
            ciphertext = data
    else:
        data = text.encode('utf-8')
        padding_len = 16 - (len(data) % 16)
        data += bytes([padding_len]*padding_len)
        if mode in ["CBC", "CTR"]:
            iv_or_nonce = os.urandom(16)
        else:
            iv_or_nonce = b''

    # wybór trybu
    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_or_nonce), backend=default_backend())
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_or_nonce), backend=default_backend())
    else:
        raise ValueError("Nieznany tryb AES")

    encryptor_or_decryptor = cipher.decryptor() if decrypt else cipher.encryptor()
    result_bytes = encryptor_or_decryptor.update(ciphertext if decrypt else data) + encryptor_or_decryptor.finalize()

    if decrypt:
        if mode not in ["ECB"]:
            padding_len = result_bytes[-1]
            result_bytes = result_bytes[:-padding_len]
        return result_bytes.decode('utf-8')
    else:
        return base64.b64encode(iv_or_nonce + result_bytes).decode('utf-8')

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    encrypted = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt(text, private_key):
    encrypted_bytes = base64.b64decode(text)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikacja szyfrująca")
        self.root.geometry("700x550")

        ttk.Label(root, text="Aplikacja szyfrująca", font=("Arial", 18, "bold")).pack(pady=10)

        #  algorytmy
        self.algorithms_map = {
            "Cezar": caesar_cipher,
            "Vigenère": vigenere_cipher,
            "Running Key": running_key_cipher,
            "AES": aes_encrypt,
            "RSA": None
        }

        self.rsa_private_key = None
        self.rsa_public_key = None

        ttk.Label(root, text="Wybierz algorytm:").pack()
        self.algorithm_var = tk.StringVar(value="Cezar")
        alg_box = ttk.Combobox(root, textvariable=self.algorithm_var,
                               values=list(self.algorithms_map.keys()), state="readonly")
        alg_box.pack(pady=5)
        alg_box.bind("<<ComboboxSelected>>", self.update_key_hint)

        self.key_label = ttk.Label(root, text="Podaj klucz (liczba całkowita):")
        self.key_label.pack(pady=5)

        vcmd = (root.register(self.validate_key_input), "%P")
        self.key_entry = ttk.Entry(root, validate="key", validatecommand=vcmd)
        self.key_entry.insert(0, "3")
        self.key_entry.pack(pady=5)

        self.aes_mode_var = tk.StringVar(value="CBC")
        self.aes_mode_box = ttk.Combobox(root, textvariable=self.aes_mode_var,
                                         values=["ECB","CBC","CTR"], state="readonly")
        #self.aes_mode_box.pack(pady=5)

        ttk.Label(root, text="Tekst do zaszyfrowania / odszyfrowania:").pack()
        self.text_input = tk.Text(root, height=5)
        self.text_input.pack(fill="x", padx=10, pady=5)

        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Szyfruj tekst", command=self.encrypt_text).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Odszyfruj tekst", command=self.decrypt_text).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Szyfruj plik", command=self.encrypt_file).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Odszyfruj plik", command=self.decrypt_file).grid(row=1, column=1, padx=5, pady=5)
        rsa_frame = ttk.Frame(root)
        rsa_frame.pack(pady=5)
        ttk.Button(rsa_frame, text="Zapisz klucze RSA", command=self.save_rsa_keys).grid(row=0, column=0, padx=5)
        ttk.Button(rsa_frame, text="Wczytaj klucze RSA", command=self.load_rsa_keys).grid(row=0, column=1, padx=5)
        

        ttk.Label(root, text="Wynik:").pack()
        self.result_box = tk.Text(root, height=6)
        self.result_box.pack(fill="x", padx=10, pady=5)

        self.hint_label = ttk.Label(root, text="➡ Klucz musi być liczbą całkowitą dla Cezara.", foreground="gray")
        self.hint_label.pack(pady=5)

    def update_key_hint(self, event=None):
        alg = self.algorithm_var.get()
        self.aes_mode_box.pack_forget()
        if alg == "Cezar":
            self.key_label.config(text="Podaj klucz (liczba całkowita):")
            self.hint_label.config(text="➡ Klucz musi być liczbą całkowitą.")
        elif alg == "Vigenère":
            self.key_label.config(text="Podaj klucz (słowo):")
            self.hint_label.config(text="➡ Klucz to słowo (np. 'tajne').")
        elif alg == "Running Key":
            self.key_label.config(text="Podaj klucz (długi tekst):")
            self.hint_label.config(text="➡ Klucz musi być co najmniej tak długi jak tekst.")
        elif alg == "AES":
            self.key_label.config(text="Podaj klucz (16, 24 lub 32 znaki):")
            self.hint_label.config(text="➡ Klucz musi mieć 16, 24 lub 32 znaki. Wybierz tryb AES poniżej.", foreground="gray") 
            self.aes_mode_box.pack(pady=5)
        elif alg == "RSA":
            self.key_label.config(text="Klucze RSA będą generowane automatycznie")
            self.hint_label.config(text="➡ RSA generuje parę kluczy publiczny/prywatny.", foreground="gray")

        self.key_entry.delete(0, tk.END)

    def validate_key_input(self, new_value):
        alg = self.algorithm_var.get()
        if alg == "Cezar":
            return new_value.isdigit() or new_value == ""
        return True

    def save_rsa_keys(self):
        if self.rsa_private_key is None or self.rsa_public_key is None:
            messagebox.showwarning("Uwaga", "Klucze RSA nie zostały wygenerowane.")
            return
        priv_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz prywatny")
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Zapisz klucz publiczny")
        if priv_path and pub_path:
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

    def load_rsa_keys(self):
        priv_path = filedialog.askopenfilename(title="Wybierz klucz prywatny", filetypes=[("PEM files", "*.pem")])
        pub_path = filedialog.askopenfilename(title="Wybierz klucz publiczny", filetypes=[("PEM files", "*.pem")])
        if priv_path and pub_path:
            with open(priv_path, "rb") as f:
                self.rsa_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(pub_path, "rb") as f:
                self.rsa_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            messagebox.showinfo("Sukces", "Klucze RSA wczytane pomyślnie.")
            
    def process_text(self, decrypt=False):
        alg_name = self.algorithm_var.get()
        algorithm = self.algorithms_map[alg_name]
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()

        try:
            if alg_name == "Cezar":
                key = int(key)
            if alg_name in ["Vigenère", "Running Key"] and not key.isalpha():
                raise ValueError("Klucz musi zawierać tylko litery.")
            if alg_name == "AES" and len(key) not in (16,24,32):
                raise ValueError("Klucz AES musi mieć długość 16,24 lub 32 znaków.")

            if alg_name == "RSA":
                if self.rsa_private_key is None or self.rsa_public_key is None:
                    self.rsa_private_key, self.rsa_public_key = generate_rsa_keys()
                result = rsa_decrypt(text, self.rsa_private_key) if decrypt else rsa_encrypt(text, self.rsa_public_key)
            elif alg_name == "AES":
                mode = self.aes_mode_var.get()
                result = algorithm(text, key, mode=mode, decrypt=decrypt)
            else:
                result = algorithm(text, key, decrypt=decrypt)

            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, result)

        except Exception as e:
            messagebox.showerror("Błąd", f"Wystąpił problem: {e}")

    def encrypt_text(self):
        self.process_text(decrypt=False)

    def decrypt_text(self):
        self.process_text(decrypt=True)

    def process_file(self, decrypt=False):
        file_path = filedialog.askopenfilename(title="Wybierz plik")
        if not file_path:
            return
        try:
            alg_name = self.algorithm_var.get()
            algorithm = self.algorithms_map[alg_name]
            key = self.key_entry.get().strip()
            if alg_name == "Cezar":
                key = int(key)
            if alg_name in ["Vigenère","Running Key"] and not key.isalpha():
                raise ValueError("Klucz musi zawierać tylko litery.")
            if alg_name=="AES" and len(key) not in (16,24,32):
                raise ValueError("Klucz AES musi mieć długość 16,24 lub 32 znaków.")

            with open(file_path, "r", encoding="utf-8") as f:
                data = f.read()

            if alg_name == "RSA":
                if self.rsa_private_key is None or self.rsa_public_key is None:
                    self.rsa_private_key, self.rsa_public_key = generate_rsa_keys()
                result = rsa_decrypt(data, self.rsa_private_key) if decrypt else rsa_encrypt(data, self.rsa_public_key)
            elif alg_name=="AES":
                mode = self.aes_mode_var.get()
                result = algorithm(data, key, mode=mode, decrypt=decrypt)
            else:
                result = algorithm(data, key, decrypt=decrypt)

            save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Zapisz wynik")
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(result)
                messagebox.showinfo("Sukces", "Operacja zakończona pomyślnie.")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def encrypt_file(self):
        self.process_file(decrypt=False)

    def decrypt_file(self):
        self.process_file(decrypt=True)

    
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
    
