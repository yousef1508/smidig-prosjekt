import customtkinter as ctk

def on_back_click():
    print("Back button clicked")

def on_forward_click():
    print("Forward button clicked")

def create_navbar(root):
    back_button = ctk.CTkButton(
        root, text="<-", command=on_back_click,
        fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0,
        width=1  # Set width to 1 to automatically adjust based on text size
    )
    back_button.place(x=160, y=10)  # Set position 160px from the left and 10px from the top

    forward_button = ctk.CTkButton(
        root, text="->", command=on_forward_click,
        fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0,
        width=1  # Set width to 1 to automatically adjust based on text size
    )
    forward_button.place(x=190, y=10)  # Set position 220px from the left and 10px from the top
