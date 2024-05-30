import customtkinter as ctk
from tkinter import messagebox
from PIL import Image
import os


def open_settings():
    messagebox.showinfo("Settings",
                        "Settings Page Opened")  # Example action, you can replace it with your settings page logic


def create_settings_button(root):
    def on_settings_click():
        open_settings()

    # Load and resize the icon
    icon_path = os.path.join(os.path.dirname(__file__), 'settings_icon.png')
    icon_image = Image.open(icon_path)
    icon_image = icon_image.resize((30, 30), Image.LANCZOS)

    # Convert the PIL image to a CTkImage
    settings_icon = ctk.CTkImage(light_image=icon_image, dark_image=icon_image, size=(30, 30))

    # Create the button with the resized icon
    settings_button = ctk.CTkButton(root, image=settings_icon, command=on_settings_click, fg_color="#a9dfd8",
                                    hover_color="#91c9bf", text="")
    settings_button.image = settings_icon  # Keep a reference to the image to prevent garbage collection

    # Position the button at the top right corner, relative to the root window size
    settings_button.place(relx=1.0, y=10, anchor='ne')  # Position at top right corner, y=10 pixels from the top

    return settings_button


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Options: "dark", "light"
    ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

    root = ctk.CTk()
    root.geometry("800x600")  # Set the size of the window
    create_settings_button(root)
    root.mainloop()
