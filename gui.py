# External Libraries
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Internal Libraries
from xts_mode import XTSAESMode

class XTSAESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("XTS-AES-256 Encryption/Decryption")
        self.geometry("600x300")

        self.key_entry_label = tk.Label(text="Key")
        self.key_entry_label.pack()

        self.key_entry = tk.Entry(self, width=70)
        self.key_entry.pack(pady=10)

        self.tweak_entry_label = tk.Label(text="Tweak")
        self.tweak_entry_label.pack()

        self.tweak_entry = tk.Entry(self, width=50)
        self.tweak_entry.pack(pady=10)

        self.input_file_button = tk.Button(self, text="Select Input File", command=self.select_input_file)
        self.input_file_button.pack(pady=5)

        self.encrypt_button = tk.Button(self, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(self, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        self.input_file = None
        self.key = None

    def select_input_file(self):
        self.input_file = filedialog.askopenfilename()

    def encrypt(self):
        key_str = self.key_entry.get()
        tweak_str = self.tweak_entry.get()

        print("Key str: " + str(key_str))
        print("Tweak str: " + str(tweak_str))

        key = bytes.fromhex(key_str)
        tweak = bytes.fromhex(tweak_str)

        print("Key: " + str(key))
        print("Tweak: " + str(tweak))

        if not self.input_file:
            print("Please select an input file.")
            return
        
        if len(key) != 32:
            print("Key should be 32 bytes (256 bits). Current length: " + str(len(key)))
            return
        
        if len(tweak) != 16:
            print("Tweak should be 16 bytes (128 bits). Current length: " + str(len(tweak)))


        xts = XTSAESMode(key, tweak)
        with open(self.input_file, "rb") as f:
            plaintext = f.read()

        ciphertext = xts.encrypt(plaintext)

        output_file = filedialog.asksaveasfilename()
        with open(output_file, "wb") as f:
            f.write(ciphertext)

        print(f"Encryption successful. Output file: {output_file}")

    def decrypt(self):
        key_str = self.key_entry.get()
        tweak_str = self.tweak_entry.get()

        print("Key str: " + str(key_str))
        print("Tweak str: " + str(tweak_str))

        key = bytes.fromhex(key_str)
        tweak = bytes.fromhex(tweak_str)

        print("Key: " + str(key))
        print("Tweak: " + str(tweak))

        if not self.input_file:
            print("Please select an input file.")
            return
        
        if len(key) != 32:
            print("Key should be 32 bytes (256 bits). Current length: " + str(len(key)))
            return
        
        if len(tweak) != 16:
            print("Tweak should be 16 bytes (128 bits). Current length: " + str(len(tweak)))

        xts = XTSAESMode(key, tweak)
        with open(self.input_file, "rb") as f:
            ciphertext = f.read()

        plaintext = xts.decrypt(ciphertext)

        output_file = filedialog.asksaveasfilename()
        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"Decryption successful. Output file: {output_file}")