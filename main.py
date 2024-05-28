import tkinter as tk
from components.download_btn.download_btn import create_save_button
from components.home_btn.home_btn import create_home_button
from components.analyze_btn.analyze_btn import create_analysis_widgets

def main():
    root = tk.Tk()
    root.title("Tkinter Example")

    width_percentage = 0.7
    height_percentage = 0.7

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    window_width = int(screen_width * width_percentage)
    window_height = int(screen_height * height_percentage)

    x_position = (screen_width - window_width) // 2
    y_position = (screen_height - window_height) // 2

    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    # Initialize the main UI components
    initialize_main_ui(root)

    root.mainloop()

def initialize_main_ui(root):
    bg_color = "#2e2e2e"
    root.configure(bg=bg_color)

    label = tk.Label(root, text="Hello, Tkinter!", fg="white", bg=bg_color)
    label.pack(pady=20)

    # Create the save button using the download component
    create_save_button(root)

    # Create the analyze widgets (Combobox and Analyze button) using the analyze component
    create_analysis_widgets(root)

    # Create the home button using the home button component
    create_home_button(root, initialize_main_ui)

if __name__ == "__main__":
    main()
