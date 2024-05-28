import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
import os

def upload_memory_dump():
    """Open a file dialog to select a memory dump file."""
    file_path = filedialog.askopenfilename(
        defaultextension=".mem",
        filetypes=[("Memory Dump Files", "*.mem"), ("All Files", "*.*")]
    )
    return file_path

def create_upload_button(parent):
    """Create an upload button for memory dump files with an image."""
    current_dir = os.path.dirname(__file__)
    icon_path = os.path.join(current_dir, "upload.png")
    icon_image = Image.open(icon_path)
    icon_image = icon_image.resize((35, 35), Image.LANCZOS)  # Resize to 35x35 pixels
    icon = ImageTk.PhotoImage(icon_image)

    upload_button = tk.Button(
        parent,
        text="Upload Memory Dump",
        command=lambda: print(f"Selected file: {upload_memory_dump()}"),
        image=icon,
        compound="right",  # Place the image to the right of the text
        bg="#A9DFD8",
        fg="black",
        font=("Roboto", 12),
        relief=tk.FLAT,
        borderwidth=0,
        padx=20,
        pady=17
    )
    upload_button.image = icon  # Keep a reference to the image to prevent garbage collection
    upload_button.config(width=200, height=50)  # Adjust the size of the button
    upload_button.pack(pady=20)  # Place the button in the parent with padding
    return upload_button
