import customtkinter as ctk
from components.download_btn.download_btn import create_save_button
from components.home_btn.home_btn import create_home_button
from components.analyze_btn.analyze_btn import create_analysis_widgets
from components.upload_btn.memory_upload import create_upload_button, upload_memory_dump
from components.settings_btn.settings import create_settings_button

def main():
    ctk.set_appearance_mode("dark")  # Modes: "System" (default), "Dark", "Light"
    ctk.set_default_color_theme("dark-blue")  # Themes: "blue" (default), "dark-blue", "green"

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

    # Initialize the main UI components
    initialize_main_ui(root)

    root.mainloop()

def initialize_main_ui(root):
    bg_color = "#262626"
    root.configure(fg_color=bg_color)

    # Variable to store the uploaded file path
    uploaded_file = ctk.StringVar()

    # Create the upload button and update the variable with the file path
    def get_uploaded_file():
        file_path = upload_memory_dump()
        uploaded_file.set(file_path)
        print(f"Uploaded file: {file_path}")
        return file_path

    create_upload_button(root)

    # Create the save button using the download component
    create_save_button(root)

    # Create the analyze widgets (Combobox and Analyze button) using the analyze component
    create_analysis_widgets(root, get_uploaded_file)

    # Create the home button using the home button component
    create_home_button(root, initialize_main_ui)

    # Create the settings button using the settings component
    create_settings_button(root)

if __name__ == "__main__":
    main()
