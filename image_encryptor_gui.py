from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image, ImageTk
import io
import os

class ImageEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")
        self.root.geometry("500x400")
        
        # Key and IV storage
        self.key = None
        self.iv = None
        
        # GUI Elements
        self.create_widgets()
    
    def create_widgets(self):
        Label(self.root, text="Image Encryption Tool", font=("Arial", 16)).pack(pady=20)
        
        btn_frame = Frame(self.root)
        btn_frame.pack(pady=20)
        
        Button(btn_frame, text="Encrypt Image", command=self.encrypt_image, 
              width=15, height=2).grid(row=0, column=0, padx=10)
        Button(btn_frame, text="Decrypt Image", command=self.decrypt_image,
              width=15, height=2).grid(row=0, column=1, padx=10)
        
        self.img_label = Label(self.root)
        self.img_label.pack(pady=20)
        
        self.status = StringVar()
        self.status.set("Ready")
        Label(self.root, textvariable=self.status, relief=SUNKEN, anchor=W).pack(fill=X, side=BOTTOM)
    
    def encrypt_image(self):
        file_path = filedialog.askopenfilename(title="Select Image to Encrypt",
                                               filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if not file_path:
            return
            
        try:
            self.key = get_random_bytes(32)  # AES-256
            self.iv = get_random_bytes(16)
            
            img = Image.open(file_path)
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            data = img_bytes.getvalue()
            
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            
            output_path = os.path.splitext(file_path)[0] + ".enc"
            with open(output_path, 'wb') as f:
                f.write(self.iv + encrypted_data)
            
            self.show_image(img)
            self.status.set(f"Encrypted: {output_path}")
            
            messagebox.showinfo("Success", 
                                f"Image encrypted successfully!\n\n"
                                f"🔑 Key (hex): {self.key.hex()}\n"
                                f"🔐 IV stored in file automatically.\n\n"
                                "✅ Save this key securely to decrypt the image.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_image(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted File",
                                               filetypes=[("Encrypted Files", "*.enc")])
        if not file_path:
            return
            
        try:
            key_hex = simpledialog.askstring("Decryption Key", "Enter the 64-character hex key:")
            if not key_hex or len(key_hex) != 64:
                messagebox.showerror("Error", "Invalid key! Must be 64-character hex string.")
                return
            try:
                self.key = bytes.fromhex(key_hex)
            except ValueError:
                messagebox.showerror("Error", "Key contains non-hexadecimal characters!")
                return

            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            self.iv = data[:16]
            encrypted_data = data[16:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            img = Image.open(io.BytesIO(decrypted_data))
            output_path = os.path.splitext(file_path)[0] + "_decrypted.png"
            img.save(output_path)
            
            self.show_image(img)
            self.status.set(f"Decrypted: {output_path}")
            messagebox.showinfo("Success", "Image decrypted successfully!")
            
        except ValueError as ve:
            messagebox.showerror("Error", f"Decryption failed: {str(ve)}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
    
    def show_image(self, img):
        img.thumbnail((300, 300))
        photo = ImageTk.PhotoImage(img)
        self.img_label.config(image=photo)
        self.img_label.image = photo  # Keep reference

if __name__ == "__main__":
    root = Tk()
    app = ImageEncryptorGUI(root)
    root.mainloop()
