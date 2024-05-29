import customtkinter as ctk
import os

def on_home_enter(event):
    event.widget.configure(fg_color="#c3e4ed")

def on_home_leave(event):
    event.widget.configure(fg_color="#a9dfd8")

def on_home_click(event):
    event.widget.configure(fg_color="white")

def create_home_button(root, initialize_main_ui):
    home_button = ctk.CTkButton(
        root, text="Home", command=lambda: redirect_to_main_page(root, initialize_main_ui),
        fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0
    )
    home_button.place(x=10, y=10)

    home_button.bind("<Enter>", on_home_enter)
    home_button.bind("<Leave>", on_home_leave)
    home_button.bind("<Button-1>", on_home_click)

def redirect_to_main_page(root, initialize_main_ui):
    for widget in root.winfo_children():
        widget.destroy()
    initialize_main_ui(root)

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.geometry("800x600")
    create_home_button(root, lambda root: print("Main UI initialized"))
    root.mainloop()
