# Do Not Use Yet!!!!
#import and main def for main.py:
#create_pagination_buttons(root)  # Create pagination buttons
#from components.pagination_btn.pagination import create_pagination_buttons

import customtkinter as ctk

def on_pagination_click(page_number):
    print(f"Page {page_number} button clicked")

def create_pagination_buttons(root):
    button_texts = ["1", "2", "3"]
    button_commands = [lambda: on_pagination_click(1), lambda: on_pagination_click(2), lambda: on_pagination_click(3)]
    buttons = {}

    root.update_idletasks()  # Ensure the window has been updated to get correct dimensions
    screen_width = root.winfo_width()
    screen_height = root.winfo_height()
    button_width = 30  # Assume each button width as 30px
    button_height = 30  # Assume each button height as 30px
    spacing = 10  # Space between buttons

    total_width = len(button_texts) * (button_width + spacing) - spacing
    start_x = (screen_width - total_width) // 2
    y_position = screen_height - button_height - 10  # 10px from the bottom

    for i, text in enumerate(button_texts):
        button = ctk.CTkButton(
            root, text=text, command=button_commands[i],
            fg_color="#a9dfd8", hover_color="#91c9bf", text_color="black", border_width=0,
            width=button_width, height=button_height
        )
        button.place(x=start_x + i * (button_width + spacing), y=y_position)
        buttons[text] = button

    return buttons


