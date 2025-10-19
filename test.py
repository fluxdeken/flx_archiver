from tkinter import *
from tkinter import ttk, messagebox, filedialog, PhotoImage

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from pathlib import Path
import os
import random

entry: Entry = None

files = []

def choose_files():
    global files
    files = filedialog.askopenfilenames(
    title="Выберите файл",
    filetypes=[("All files", "*.*")])

def get_key_from_password(password: str, salt=None):
    
    if salt==None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )

    password = password.encode("utf-8")
    key = kdf.derive(password)
    return key, salt

def encrypt_files():

    global files, pswrd
    
    amount_of_files = len(files)
    if amount_of_files == 0:
        messagebox.showerror("Error", "No files have been chosen.")
        return False
    
    for file in files:
        path = Path(file)
        if not path.exists():
            messagebox.showerror("Error", "1 or more files doesn't exist.")
            return False

    alph = "abcdefghijklmnopqrstuvwxyz0123456789"
    alph_len = len(alph)

    archive_name = "flx_"
    for _ in range(16):
        archive_name += alph[random.randrange(0, alph_len)]
    #archive_name += ".flx"

    archive_path = Path(Path(files[0]).parent).joinpath(archive_name)
    
    key, salt = get_key_from_password(pswrd.get())
    aesgcm = AESGCM(key)
    
    with open(archive_path, "ab") as arch_file:
        arch_file.write(salt)
        arch_file.write(amount_of_files.to_bytes(length=4))
        for file_name in files:
            with open(file_name, "rb") as enc_file:

                nonce_buff : bytes = os.urandom(12)
                name_buff : bytes = Path(file_name).name.encode("utf-8")
                file_buff: bytes = enc_file.read()
                
                buff_to_encrypt:bytes = len(name_buff).to_bytes(length=4) + name_buff + \
                    len(file_buff).to_bytes(length=4) + file_buff
                
                encrypted:bytes = aesgcm.encrypt(nonce_buff, buff_to_encrypt, None)

                full_size = len(encrypted)

                arch_file.write(nonce_buff)
                arch_file.write(full_size.to_bytes(length=4))
                arch_file.write(encrypted)

    messagebox.showinfo("Success", "Successfully encrypted.")
    return True

def decrypt_files():
    global files, pswrd
    if len(files) == 0:
        messagebox.showerror("Error", "No files have been chosen.")
        return False
    
    for file in files:
        path = Path(file)
        if not path.exists():
            messagebox.showerror("Error", "1 or more files doesn't exist.")
            return False
        #elif path.suffix != ".flx":
        #    messagebox.showerror("Error", "File extension if wrong")
        #    return False
        
    
    for file in files:

        with open(file, "rb") as fin:
            try:
                salt:bytes = fin.read(16)
                key, salt = get_key_from_password(pswrd.get(), salt=salt)
                aesgcm = AESGCM(key)

                amount:int = int.from_bytes(fin.read(4))
                
                for _ in range(amount):
                    nonce = fin.read(12)
                    
                    full_size = int.from_bytes(fin.read(4))
                    to_decrypt = fin.read(full_size)
                    decrypted:bytes = aesgcm.decrypt(nonce, to_decrypt, None)
                
                    name_size = int.from_bytes(decrypted[0:4])
                    name = decrypted[4:name_size+4].decode("utf-8")
                    buff_size = int.from_bytes(decrypted[name_size+4:name_size+8])
                    buff = decrypted[name_size+8:name_size+8+buff_size]

                    file_path = Path(Path(file).parent).joinpath(name)

                    with open(file_path, "wb") as fout:
                        fout.write(buff)

            except InvalidTag:
                messagebox.showerror("Error", "Wrong password.")
                return False
            except: 
                messagebox.showerror("Error", "Unknown error.")
                return False
            
    messagebox.showinfo("Success", "Successfully decrypted.")
    return True


root = Tk()
root.title("FLX Archiver")
root.iconbitmap("img/cab_history_archive_archives_7219.ico")

frm = ttk.Frame(root, padding=10)
frm.grid()

ttk.Button(frm, text="Choose Files", command=choose_files).grid(column=0, row=0, padx=10, pady=10)
ttk.Button(frm, text="Encrypt", command=encrypt_files).grid(column=1, row=0, padx=10, pady=10)
ttk.Button(frm, text="Decrypt", command=decrypt_files).grid(column=2, row=0, padx=10, pady=10)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=3, row=0, padx=10, pady=10)

label_ps = ttk.Label(frm, text="Password:")
label_ps.grid(column=0, row=1)

pswrd = ttk.Entry(frm, width=40)
pswrd.grid(column=1, row=1, columnspan=3)

root.mainloop()