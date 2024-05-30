import customtkinter as ctk
from tkinter import messagebox
from components.navbar_btn.navbar import create_navbar
from components.download_btn.download_btn import create_save_button
from components.home_btn.home_btn import create_home_button
from components.analyze_btn.analyze_btn import create_analysis_widgets
from components.upload_btn.memory_upload import create_upload_button
from components.settings_btn.settings import create_settings_button

# Correct import statement
from components.recently_used_plugins_buttons.recentlyusedplugins import create_recently_used_plugins

def initialize_main_ui(root):
    try:
        file_path = create_upload_button(root)
        create_save_button(root)
        create_analysis_widgets(root, file_path)
        create_home_button(root, initialize_main_ui)
        create_settings_button(root)

        # Create Navbar instance and pass the root window
        create_navbar(root)

        # Create recently used plugins section
        create_recently_used_plugins(root)
    except Exception as e:
        # Show error message box
        messagebox.showerror("Error", f"An error occurred: {e}")

def main():
    try:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        root = ctk.CTk()
        width_percentage = 0.7
        height_percentage = 0.7

        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        window_width = int(screen_width * width_percentage)
        window_height = int(screen_height * height_percentage)

        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2

        root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

        # Uncomment to test error handling
        # test_error()

        initialize_main_ui(root)
        root.mainloop()
    except Exception as e:
        # Show error message box
        messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    main()
