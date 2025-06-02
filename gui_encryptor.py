import tkinter as tk
from tkinter import filedialog, messagebox
import os
from encryptor import encrypt_file, decrypt_file

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Utility")
        self.root.geometry("400x300")

        # File selection
        tk.Label(root, text="Select File:").pack(pady=10)
        self.file_entry = tk.Entry(root, width=40)
        self.file_entry.pack()
        tk.Button(root, text="Browse", command=self.browse_file).pack()

        # Password input
        tk.Label(root, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.pack()

        # Buttons for encrypt/decrypt
        tk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt).pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def encrypt(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        if not file_path or not password:
            messagebox.showerror("Error", "Please provide file and password")
            return
        try:
            encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"Encrypted file saved as {file_path}.enc")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        if not file_path or not password:
            messagebox.showerror("Error", "Please provide file and password")
            return
        try:
            decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"Decrypted file saved as {file_path.replace('.enc', '.dec')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()