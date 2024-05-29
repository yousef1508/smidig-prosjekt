import customtkinter as ctk
from PIL import Image, ImageTk
import os


def on_home_enter(event):
    event.widget.configure(fg_color="#c3e4ed")  # Change to a lighter color to simulate glow


def on_home_leave(event):
    event.widget.configure(fg_color="#a9dfd8")  # Restore original color


def on_home_click(event):
    event.widget.configure(fg_color="white")  # Change color to white on click


def create_home_button(root, initialize_main_ui):
    # Load and resize the home icon
    current_dir = os.path.dirname(__file__)
    icon_path = os.path.join(current_dir, "home_icon.png")
    icon_image = Image.open(icon_path)
    icon_image = icon_image.resize((30, 30), Image.LANCZOS)  # Resize to 30x30 pixels
    icon = ImageTk.PhotoImage(icon_image)

    # Create the button with the resized image and text
    home_button = ctk.CTkButton(
        root, text="Home", command=lambda: redirect_to_main_page(root, initialize_main_ui),
        image=icon, compound="top", fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0
    )
    home_button.image = icon  # Keep a reference to the image to prevent garbage collection
    home_button.place(x=10, y=10)  # Place the button in the top left corner

    # Bind mouse events
    home_button.bind("<Enter>", on_home_enter)
    home_button.bind("<Leave>", on_home_leave)
    home_button.bind("<Button-1>", on_home_click)


def redirect_to_main_page(root, initialize_main_ui):
    for widget in root.winfo_children():
        widget.destroy()
    initialize_main_ui(root)  # Reinitialize the main UI components


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Options: "dark", "light"
    ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

    root = ctk.CTk()
    root.geometry("800x600")  # Set the size of the window
    create_home_button(root, lambda root: print("Main UI initialized"))  # Example function for initializing main UI
    root.mainloop()
