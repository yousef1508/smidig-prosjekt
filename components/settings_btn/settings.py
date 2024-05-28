# components/settings_button/settings.py
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import os

def open_settings():
    messagebox.showinfo("Settings", "Settings Page Opened")  # Example action, you can replace it with your settings page logic

def create_settings_button(root):
    def on_settings_click():
        open_settings()

    # Load and resize the icon
    icon_path = os.path.join(os.path.dirname(__file__), 'settings_icon.png')
    icon_image = Image.open(icon_path)
    icon_image = icon_image.resize((30, 30), Image.LANCZOS)
    settings_icon = ImageTk.PhotoImage(icon_image)

    # Create the button with the resized icon
    settings_button = tk.Button(root, image=settings_icon, command=on_settings_click, bg="#a9dfd8", bd=0)
    settings_button.image = settings_icon  # Keep a reference to the image to prevent garbage collection

    # Position the button at the top right corner, relative to the root window size
    settings_button.place(relx=1.0, y=10, anchor='ne')  # Position at top right corner, y=10 pixels from the top

    return settings_button