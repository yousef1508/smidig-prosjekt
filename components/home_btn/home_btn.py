import customtkinter as ctk
from PIL import Image
import os

def on_home_click(root, initialize_main_ui):
    print("Home button clicked")
    # Clear existing widgets
    for widget in root.winfo_children():
        widget.destroy()
    # Re-initialize the main UI
    if initialize_main_ui is not None:
        initialize_main_ui(root)

def create_home_button(root, initialize_main_ui):
    # Load and resize the icon
    icon_path = os.path.join(os.path.dirname(__file__), 'home_icon.png')
    icon_image = Image.open(icon_path)
    icon_image = icon_image.resize((30, 30), Image.LANCZOS)

    # Convert the PIL image to a CTkImage
    home_icon = ctk.CTkImage(light_image=icon_image, dark_image=icon_image, size=(30, 30))

    # Create the button with the resized icon and text
    home_button = ctk.CTkButton(root, image=home_icon, command=lambda: on_home_click(root, initialize_main_ui),
                                fg_color="#a9dfd8", hover_color="#91c9bf", text="Home", compound="left",
                                text_color="black", font=("Arial", 14))
    home_button.image = home_icon  # Keep a reference to the image to prevent garbage collection

    # Position the button at the top left corner, relative to the root window size
    home_button.place(relx=0.0, y=10, anchor='nw')  # Position at top left corner, y=10 pixels from the top

    return home_button

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Options: "dark", "light"
    ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

    root = ctk.CTk()
    root.geometry("800x600")  # Set the size of the window
    create_home_button(root, None)
    root.mainloop()
