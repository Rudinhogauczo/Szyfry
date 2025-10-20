import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# algorytmy szyfrowania 
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


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie plików i tekstu")
        self.root.geometry("600x420")

        ttk.Label(root, text="Aplikacja szyfrująca", font=("Arial", 18, "bold")).pack(pady=10)

        # miejsce na algorytmy 
        self.algorithms_map = {
            "Cezar": caesar_cipher,
            "Vigenère": vigenere_cipher,
            "Running Key": running_key_cipher
        }

        ttk.Label(root, text="Wybierz algorytm:").pack()
        self.algorithm_var = tk.StringVar(value="Cezar")
        alg_box = ttk.Combobox(root, textvariable=self.algorithm_var,
                               values=list(self.algorithms_map.keys()), state="readonly")
        alg_box.pack(pady=5)
        alg_box.bind("<<ComboboxSelected>>", self.update_key_hint)

        self.key_label = ttk.Label(root, text="Podaj klucz (liczba całkowita):")
        self.key_label.pack()

        vcmd = (root.register(self.validate_key_input), "%P")
        self.key_entry = ttk.Entry(root, validate="key", validatecommand=vcmd)
        self.key_entry.insert(0, "3")
        self.key_entry.pack(pady=5)

        ttk.Label(root, text="Tekst do zaszyfrowania / odszyfrowania:").pack()
        self.text_input = tk.Text(root, height=5)
        self.text_input.pack(fill="x", padx=10, pady=5)

        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Szyfruj tekst", command=self.encrypt_text).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Odszyfruj tekst", command=self.decrypt_text).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Szyfruj plik", command=self.encrypt_file).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Odszyfruj plik", command=self.decrypt_file).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(root, text="Wynik:").pack()
        self.result_box = tk.Text(root, height=6)
        self.result_box.pack(fill="x", padx=10, pady=5)

        self.hint_label = ttk.Label(root, text="Klucz musi być liczbą całkowitą dla szyfru Cezara.")
        self.hint_label.pack(pady=5)

    def update_key_hint(self, event=None):
        alg = self.algorithm_var.get()
        if alg == "Cezar":
            self.key_label.config(text="Podaj klucz (liczba całkowita):")
            self.hint_label.config(text="➡ Klucz musi być liczbą całkowitą.")
        elif alg == "Vigenère":
            self.key_label.config(text="Podaj klucz (słowo):")
            self.hint_label.config(text="➡ Klucz to słowo (np. 'tajne').")
        elif alg == "Running Key":
            self.key_label.config(text="Podaj klucz (długi tekst):")
            self.hint_label.config(text="➡ Klucz musi być co najmniej tak długi jak tekst.")
        self.key_entry.delete(0, tk.END)

    def validate_key_input(self, new_value):
        alg = self.algorithm_var.get()
        if alg == "Cezar":
            return new_value.isdigit() or new_value == ""
        return True

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
            result = algorithm(text, key, decrypt=decrypt)
            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, result)
        except ValueError as e:
            messagebox.showerror("Błąd", str(e))
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
            if key.isdigit():
                key = int(key)
            with open(file_path, "r", encoding="utf-8") as f:
                data = f.read()
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

