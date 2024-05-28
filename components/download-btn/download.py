# components/download-btn/download.py
import tkinter as tk
from tkinter import filedialog

def save_result():
    def save():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"),
                                                            ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write("Your result text goes here")

    return save

def create_save_button(root):
    save_button = tk.Button(root, text="Save Result", command=save_result())
    save_button.pack(pady=10)
