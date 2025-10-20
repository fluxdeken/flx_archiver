from tkinter import *
from tkinter import ttk, messagebox, filedialog, PhotoImage

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from pathlib import Path
import os
import random

from typing import List, Tuple

entry: Entry = None

class Encryptor:
    def __init__(self):
        self.files = []
        self.folders = []

    def choose_files(self):
        self.files += list(filedialog.askopenfilenames(
        title="Выберите файл",
        filetypes=[("All files", "*.*")]))

    def choose_folder(self):
        folder_path = filedialog.askdirectory(
            title="Choose path"
        )
        if folder_path != "":
            self.folders.append(folder_path)

    def clear(self):
        self.files.clear()
        self.folders.clear()

    def get_key_from_password(self, password: str, salt=None):
        
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

    def encrypt_files(self):

        global pswrd
        
        folders_paths = self.get_all_files_and_relative_paths(self.folders)
        amount_of_files = len(self.files) + len(folders_paths)

        if amount_of_files == 0:
            messagebox.showwarning("Error", "No files have been chosen.")
            return False
        
        for file in self.files:
            path = Path(file)
            if not path.exists():
                messagebox.showwarning("Error", "1 or more files doesn't exist.")
                return False

        alph = "abcdefghijklmnopqrstuvwxyz0123456789"
        alph_len = len(alph)

        archive_name = "archieve_"
        for _ in range(12):
            archive_name += alph[random.randrange(0, alph_len)]
        
        #archive_path = Path.cwd()
        #if len(folders_paths) != 0:
        #    archive_path = Path(Path(Path(folders_paths[0][0]).parent).parent).joinpath(archive_name)
        #else:
        #    archive_path = Path(Path(self.files[0]).parent).joinpath(archive_name)
        archive_path = Path.cwd().joinpath("archives")
        archive_path.mkdir(parents=True, exist_ok=True)
        archive_path /= archive_name
        
        key, salt = self.get_key_from_password(pswrd.get())
        aesgcm = AESGCM(key)
        
        with open(archive_path, "ab") as arch_file:
            arch_file.write(salt)
            arch_file.write(amount_of_files.to_bytes(length=4))
            for file_name in self.files:
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

            for tple in folders_paths:
                with open(Path(tple[0]), "rb") as enc_file:

                    nonce_buff : bytes = os.urandom(12)
                    name_buff : bytes = tple[1].encode("utf-8")
                    file_buff: bytes = enc_file.read()
                    
                    buff_to_encrypt:bytes = len(name_buff).to_bytes(length=4) + name_buff + \
                        len(file_buff).to_bytes(length=4) + file_buff
                    
                    encrypted:bytes = aesgcm.encrypt(nonce_buff, buff_to_encrypt, None)

                    full_size = len(encrypted)

                    arch_file.write(nonce_buff)
                    arch_file.write(full_size.to_bytes(length=4))
                    arch_file.write(encrypted)

        self.clear()
        messagebox.showinfo("Success", "Successfully encrypted.")
        return True

    def decrypt_files(self):
        global pswrd
        if len(self.files) == 0:
            messagebox.showwarning("Error", "No files have been chosen.")
            return False
        
        for file in self.files:
            path = Path(file)
            if not path.exists():
                messagebox.showwarning("Error", "1 or more files doesn't exist.")
                return False
            
        
        for file in self.files:

            with open(file, "rb") as fin:
                try:
                    salt:bytes = fin.read(16)
                    key, salt = self.get_key_from_password(pswrd.get(), salt=salt)
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

                        parent = Path(Path(file).parent)
                        file_path = parent.joinpath(name)
                        file_path.parent.mkdir(parents=True, exist_ok=True)

                        with open(file_path, "wb") as fout:
                            fout.write(buff)

                except InvalidTag:
                    messagebox.showwarning("Error", "Wrong password.")
                    return False
                except Exception as e:
                    messagebox.showwarning("Error", e)
                    return False
        
        self.clear()
        messagebox.showinfo("Success", "Successfully decrypted.")
        return True

    def get_all_files_and_relative_paths(self, folder_list: List[str]) -> List[Tuple[str, str]]:
        all_files_data: List[Tuple[str, str]] = []

        for root_folder_str in folder_list:
            root_path = Path(root_folder_str)
            
            parent_of_root = root_path.parent 

            for item_path in root_path.rglob('*'):
                if item_path.is_file():
                    full_path_str = str(item_path)
                    
                    relative_path_full = os.path.relpath(item_path, parent_of_root)
                    relative_path_str = str(Path(relative_path_full))
                    
                    all_files_data.append((full_path_str, relative_path_str))

        return all_files_data


encryptor = Encryptor()

root = Tk()
root.title("FLX Archiver")
root.iconbitmap("img/cab_history_archive_archives_7219.ico") 

frm = ttk.Frame(root, padding=10)
frm.grid()

ttk.Button(frm, text="Files", command=encryptor.choose_files).grid(
    column=0, row=0, padx=10, pady=10)
ttk.Button(frm, text="Folder", command=encryptor.choose_folder).grid(
    column=1, row=0, padx=10, pady=10)
ttk.Button(frm, text="Clear", command=encryptor.clear).grid(
    column=2, row=0, padx=10, pady=10)

label_ps = ttk.Label(frm, text="Password:")
label_ps.grid(column=0, row=1, sticky='w', pady=5)

pswrd = ttk.Entry(frm, width=40, show='*')
pswrd.grid(column=1, row=1, columnspan=2, sticky='we', padx=10, pady=5) 

ttk.Button(frm, text="Encrypt", command=encryptor.encrypt_files).grid(
    column=0, row=2, padx=10, pady=10)
ttk.Button(frm, text="Decrypt", command=encryptor.decrypt_files).grid(
    column=1, row=2, padx=10, pady=10)
ttk.Button(frm, text="Exit", command=root.destroy).grid(
    column=2, row=2, padx=10, pady=10)

root.mainloop()