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

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie plików i tekstu")
        self.root.geometry("600x420")

        ttk.Label(root, text="Aplikacja szyfrująca", font=("Arial", 18, "bold")).pack(pady=10)

        # miejsce na algorytmy 
        self.algorithms_map = {
            "Cezar": caesar_cipher,

        }

        ttk.Label(root, text="Wybierz algorytm:").pack()
        self.algorithm_var = tk.StringVar(value="Cezar")
        ttk.Combobox(root, textvariable=self.algorithm_var, values=list(self.algorithms_map.keys()), state="readonly").pack(pady=5)

        ttk.Label(root, text="Podaj klucz (dla Cezara liczba):").pack()
        self.key_entry = ttk.Entry(root)
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
        self.result_box = tk.Text(root, height=5)
        self.result_box.pack(fill="x", padx=10, pady=5)

    def process_text(self, decrypt=False):
        alg_name = self.algorithm_var.get()
        algorithm = self.algorithms_map[alg_name]
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()

        try:
            if key.isdigit():
                key = int(key)
            result = algorithm(text, key, decrypt=decrypt)
            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się przetworzyć tekstu:\n{e}")

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
