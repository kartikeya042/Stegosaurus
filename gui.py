import os
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox

from Project.Test import (
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    sdes_encrypt,
    sdes_decrypt,
    generate_sdes_key,
    hide_data_in_image,
    extract_data_from_image,
    hybrid_encrypt,
    hybrid_decrypt,
)


def safe_bytes(text: str) -> bytes:
    return text.encode()


class StegosaurusGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stegosaurus GUI — S-DES, RSA, Steganography")
        self.geometry("900x600")

        # Input frame
        inp_frame = tk.Frame(self)
        inp_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=False, padx=8, pady=6)

        tk.Label(inp_frame, text="Input / Plaintext:").pack(anchor="w")
        self.input_text = tk.Text(inp_frame, height=8)
        self.input_text.pack(fill=tk.X)

        # Buttons frame
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=8, pady=6)

        btn_specs = [
            ("Generate RSA Keys", self.on_generate_rsa_keys),
            ("S-DES Encrypt", self.on_sdes_encrypt),
            ("S-DES Decrypt", self.on_sdes_decrypt),
            ("RSA Encrypt", self.on_rsa_encrypt),
            ("RSA Decrypt", self.on_rsa_decrypt),
            ("Hide in Image", self.on_hide_in_image),
            ("Extract from Image", self.on_extract_from_image),
            ("Hybrid Encrypt", self.on_hybrid_encrypt),
            ("Hybrid Decrypt", self.on_hybrid_decrypt),
            ("Exit", self.quit),
        ]

        for i, (label, cmd) in enumerate(btn_specs):
            b = tk.Button(btn_frame, text=label, command=cmd)
            b.grid(row=0, column=i, padx=4, pady=2, sticky="ew")
            btn_frame.grid_columnconfigure(i, weight=1)

        # Output frame
        out_frame = tk.Frame(self)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

        tk.Label(out_frame, text="Output / Result:").pack(anchor="w")
        self.output_text = tk.Text(out_frame)
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def _set_output(self, text: str):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)

    def _show_error(self, e: Exception):
        msg = f"Error: {e}\n" + traceback.format_exc()
        messagebox.showerror("Error", str(e))
        self._set_output(msg)

    def on_generate_rsa_keys(self):
        try:
            generate_rsa_keys()
            messagebox.showinfo("Done", "RSA key pair generated (private.pem, public.pem)")
        except Exception as e:
            self._show_error(e)

    def on_sdes_encrypt(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showinfo("Input required", "Please enter plaintext to encrypt in the Input box.")
                return
            data = safe_bytes(text)
            key10 = generate_sdes_key()
            cipher = sdes_encrypt(data, key10)

            key_path = filedialog.asksaveasfilename(defaultextension=".key", initialfile="sdes.key", title="Save S-DES key")
            if key_path:
                open(key_path, "wb").write(key10.to_bytes(2, "big"))

            enc_path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile="sdes.enc", title="Save S-DES ciphertext")
            if enc_path:
                open(enc_path, "wb").write(cipher)

            self._set_output(f"S-DES encrypted ({len(cipher)} bytes).\nKey saved: {key_path}\nCipher saved: {enc_path}")
        except Exception as e:
            self._show_error(e)

    def on_sdes_decrypt(self):
        try:
            key_file = filedialog.askopenfilename(title="Open S-DES key file")
            if not key_file:
                return
            enc_file = filedialog.askopenfilename(title="Open S-DES ciphertext file")
            if not enc_file:
                return
            key_bytes = open(key_file, "rb").read()
            key10 = int.from_bytes(key_bytes[:2], "big") & 0x3FF
            cipher = open(enc_file, "rb").read()
            plain = sdes_decrypt(cipher, key10)
            try:
                decoded = plain.decode(errors="ignore")
            except Exception:
                decoded = repr(plain)
            self._set_output(decoded)
        except Exception as e:
            self._show_error(e)

    def on_rsa_encrypt(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showinfo("Input required", "Enter plaintext in the Input box.")
                return
            data = safe_bytes(text)
            ct = rsa_encrypt(data)
            path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile="rsa.enc", title="Save RSA ciphertext")
            if path:
                open(path, "wb").write(ct)
                self._set_output(f"RSA encrypted → {path}")
        except Exception as e:
            self._show_error(e)

    def on_rsa_decrypt(self):
        try:
            path = filedialog.askopenfilename(title="Open RSA ciphertext file")
            if not path:
                return
            ct = open(path, "rb").read()
            pt = rsa_decrypt(ct)
            self._set_output(pt.decode(errors="ignore"))
        except Exception as e:
            self._show_error(e)

    def on_hide_in_image(self):
        try:
            img_path = filedialog.askopenfilename(title="Open image to hide data in", filetypes=[("Image files", "*.png;*.jpg;*.bmp;*.gif;*.tif;*.tiff"), ("All files", "*")])
            if not img_path:
                return
            data = self.input_text.get("1.0", tk.END).strip()
            if not data:
                messagebox.showinfo("Input required", "Enter data to hide in the Input box.")
                return
            out_path = filedialog.asksaveasfilename(defaultextension=".png", initialfile="encoded.png", title="Save encoded image (PNG recommended)")
            if not out_path:
                return
            hide_data_in_image(img_path, data, out_path)
            self._set_output(f"Data hidden in image → {out_path}")
        except Exception as e:
            self._show_error(e)

    def on_extract_from_image(self):
        try:
            img_path = filedialog.askopenfilename(title="Open encoded image to extract from", filetypes=[("PNG images", "*.png"), ("All files", "*")])
            if not img_path:
                return
            data_bytes = extract_data_from_image(img_path)
            try:
                text = data_bytes.decode(errors="ignore")
            except Exception:
                text = repr(data_bytes)
            save_path = filedialog.asksaveasfilename(defaultextension=".bin", initialfile="extracted_payload.bin", title="Save extracted payload")
            if save_path:
                open(save_path, "wb").write(data_bytes)
            self._set_output(f"Extracted {len(data_bytes)} bytes. Saved to: {save_path}\n\nContent:\n{text}")
        except Exception as e:
            self._show_error(e)

    def on_hybrid_encrypt(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showinfo("Input required", "Enter plaintext in the Input box.")
                return
            enc_key_blob, cipher = hybrid_encrypt(text.encode())
            key_path = filedialog.asksaveasfilename(defaultextension=".key", initialfile="hybrid.key", title="Save hybrid key blob")
            if key_path:
                open(key_path, "wb").write(enc_key_blob)
            enc_path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile="hybrid.enc", title="Save hybrid ciphertext")
            if enc_path:
                open(enc_path, "wb").write(cipher)
            self._set_output(f"Hybrid encrypted. Key: {key_path}\nCipher: {enc_path}")
        except Exception as e:
            self._show_error(e)

    def on_hybrid_decrypt(self):
        try:
            key_path = filedialog.askopenfilename(title="Open hybrid key file")
            if not key_path:
                return
            enc_path = filedialog.askopenfilename(title="Open hybrid ciphertext file")
            if not enc_path:
                return
            enc_key_blob = open(key_path, "rb").read()
            cipher = open(enc_path, "rb").read()
            pt = hybrid_decrypt(enc_key_blob, cipher)
            self._set_output(pt.decode(errors="ignore"))
        except Exception as e:
            self._show_error(e)


def main():
    app = StegosaurusGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
