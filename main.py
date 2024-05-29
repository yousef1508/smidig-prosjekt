import customtkinter as ctk
from components.download_btn.download_btn import create_save_button
from components.home_btn.home_btn import create_home_button
from components.analyze_btn.analyze_btn import create_analysis_widgets  # Updated import
from components.upload_btn.memory_upload import create_upload_button
from components.settings_btn.settings import create_settings_button

def initialize_main_ui(root):
    file_path = create_upload_button(root)  # Assuming it returns the file path
    create_save_button(root)
    create_analysis_widgets(root, file_path)  # Pass the file path to the analysis widget
    create_home_button(root, initialize_main_ui)  # Pass initialize_main_ui as an argument
    create_settings_button(root)

def main():
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

    initialize_main_ui(root)
    root.mainloop()

if __name__ == "__main__":
    main()
