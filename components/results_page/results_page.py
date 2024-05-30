import customtkinter as ctk

def result_page():
    result_root = ctk.CTk()

    width_percentage = 0.7
    height_percentage = 0.7

    screen_width = result_root.winfo_screenwidth()
    screen_height = result_root.winfo_screenheight()

    window_width = int(screen_width * width_percentage)
    window_height = int(screen_height * height_percentage)

    x_position = (screen_width - window_width) // 2
    y_position = (screen_height - window_height) // 2

    result_root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    # Initialize the main UI components
    initialize_result_ui(result_root)

    result_root.mainloop()

def initialize_result_ui(root):
    bg_color = "#262626"
    root.configure(fg_color=bg_color)

    # Add your UI components initialization here
    label = ctk.CTkLabel(root, text="This is the Result Page", fg_color=bg_color)
    label.pack(pady=20)

    button = ctk.CTkButton(root, text="Click Me", command=lambda: print("Button clicked"))
    button.pack(pady=20)

# Add a conditional block to allow direct testing
# DENNE IF KODEN SKAL FJERNES I FINALE VERSJONEN. FORDI DEN ER HER KUN FOR TEST GRUNNER.
if __name__ == "__main__":
    result_page()
