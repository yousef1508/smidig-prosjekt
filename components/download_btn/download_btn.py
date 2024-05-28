# components/download_btn/download_btn.py
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


def on_enter(event):
    event.widget.config(bg="#c3e4ed")  # Change to a lighter color to simulate glow


def on_leave(event):
    event.widget.config(bg="#a9dfd8")  # Restore original color


def on_click(event):
    event.widget.config(bg="white", fg="black")  # Change color to white on click


def create_save_button(root):
    # Load and resize the logo
    logo_path = os.path.join(os.path.dirname(__file__), 'download_logo.png')
    logo_image = Image.open(logo_path)
    logo_image = logo_image.resize((30, 30), Image.LANCZOS)
    logo = ImageTk.PhotoImage(logo_image)

    # Create the button with the resized image
    save_button = tk.Button(root, text="Download", command=save_result(), image=logo, compound="top",
                            bg="#a9dfd8", fg="black", font=("Roboto", 12), padx=10, pady=10, borderwidth=0)
    save_button.image = logo  # Keep a reference to the image to prevent garbage collection
    save_button.pack(pady=10)

    # Bind mouse events
    save_button.bind("<Enter>", on_enter)
    save_button.bind("<Leave>", on_leave)
    save_button.bind("<Button-1>", on_click)  # Binds the left mouse click

    return save_button
