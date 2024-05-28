# components/download_btn/download.py
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
import os


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
    # Load and resize the logo
    logo_path = os.path.join(os.path.dirname(__file__), 'download_logo.png')
    logo_image = Image.open(logo_path)
    logo_image = logo_image.resize((30, 30), Image.LANCZOS)  # Resize to 30x30 pixels
    logo = ImageTk.PhotoImage(logo_image)

    # Create the button with the resized image
    save_button = tk.Button(root, text="Save Result", command=save_result(), image=logo, compound="left",
                            bg="#a9dfd8", fg="black", font=("Helvetica", 12), padx=5, pady=5, borderwidth=0)
    save_button.image = logo  # Keep a reference to the image to prevent garbage collection
    save_button.pack(pady=10)
