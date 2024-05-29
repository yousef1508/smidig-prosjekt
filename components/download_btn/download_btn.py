import customtkinter as ctk
from tkinter import filedialog
import os

def save_result():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write("Your result text goes here")

def create_save_button(root):
    save_button = ctk.CTkButton(master=root, text="Download", command=save_result)
    save_button.pack(pady=20)

    return save_button

def main():
    app = ctk.CTk()
    app.title("Save File Example")

    create_save_button(app)
    app.mainloop()

if __name__ == "__main__":
    main()
