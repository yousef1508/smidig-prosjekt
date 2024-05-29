# memory_upload.py
import customtkinter as ctk
from tkinter import filedialog


def create_upload_button(root):
    file_path = None

    def upload_action():
        nonlocal file_path
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Memory Dump Files", "*.dmp")])
        if file_path:
            print("File uploaded:", file_path)

    def get_file_path():
        return file_path

    upload_button = ctk.CTkButton(root, text="Upload Memory Dump", command=upload_action)
    upload_button.pack(pady=10)

    return get_file_path
