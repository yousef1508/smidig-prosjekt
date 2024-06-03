import customtkinter as ctk
from PIL import Image
import os

def on_back_click():
    print("Back button clicked")

def on_forward_click():
    print("Forward button clicked")

def create_navbar(root):
    # Get the path to the images
    current_dir = os.path.dirname(os.path.abspath(__file__))
    back_icon_path = os.path.join(current_dir, "back_icon.png")
    forward_icon_path = os.path.join(current_dir, "forward_icon.png")

    # Load the images
    back_image = Image.open(back_icon_path).resize((40, 40), Image.ANTIALIAS)
    forward_image = Image.open(forward_icon_path).resize((40, 40), Image.ANTIALIAS)

    # Create CTkImages from the PIL images
    back_ctk_image = ctk.CTkImage(light_image=back_image, size=(30, 30))
    forward_ctk_image = ctk.CTkImage(light_image=forward_image, size=(30, 30))

    back_button = ctk.CTkButton(
        root, image=back_ctk_image, text="", command=on_back_click,
        fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0,
        width=40, height=40  # Adjust the size to fit your icons
    )
    back_button.place(x=160, y=10)  # Set position 160px from the left and 10px from the top

    forward_button = ctk.CTkButton(
        root, image=forward_ctk_image, text="", command=on_forward_click,
        fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0,
        width=40, height=40  # Adjust the size to fit your icons
    )
    forward_button.place(x=210, y=10)  # Set position 210px from the left and 10px from the top