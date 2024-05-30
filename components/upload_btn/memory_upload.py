import customtkinter as ctk
from tkinter import filedialog
from PIL import Image
import os

def create_upload_button(root):
    file_path = None

    def upload_action():
        nonlocal file_path
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Memory Dump Files", "*.mem")])
        if file_path:
            print("File uploaded:", file_path)

    def get_file_path():
        return file_path

    # Load the image
    current_dir = os.path.dirname(os.path.abspath(__file__))
    image_path = os.path.join(current_dir, "upload.png")
    image = ctk.CTkImage(light_image=Image.open(image_path), dark_image=Image.open(image_path), size=(30, 30))  # Increase the size

    # Create the upload button with the image aligned to the right, change the button color, and text color
    upload_button = ctk.CTkButton(
        root,
        text="Upload Memory Dump",
        command=upload_action,
        image=image,
        compound="right",
        fg_color="#A9DFD8",
        text_color="black"  # Change the font color to black
    )
    upload_button.pack(pady=10)

    return get_file_path

# Example usage
if __name__ == "__main__":
    root = ctk.CTk()
    root.title("Memory Upload")

    create_upload_button(root)

    root.mainloop()
