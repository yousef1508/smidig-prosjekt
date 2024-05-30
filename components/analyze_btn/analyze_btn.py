import customtkinter as ctk
import os

def create_analysis_widgets(root, get_file_path):
    # Adjust the path to point to the 'plugins' directory at the root of your project
    plugin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'plugins')
    plugins = [plugin for plugin in os.listdir(plugin_dir) if plugin.endswith('.py')]

    # Create a label for error messages, initially empty
    error_label = ctk.CTkLabel(root, text="", text_color="red")
    error_label.pack(pady=10)

    def analyze_file():
        file_path = get_file_path()
        selected_plugin = plugin_dropdown.get()
        if file_path and os.path.exists(file_path):
            print(f"Analyzing: {file_path} using {selected_plugin}")
            try:
                with open(file_path, 'r') as file:
                    data = file.read()
                    print("File contents:", data[:100])
                # Clear any error message when file read is successful
                error_label.configure(text="")
            except Exception as e:
                error_label.configure(text="Failed to read the file.")
                print("Failed to read the file:", e)
        else:
            error_label.configure(text="No file uploaded or file path is incorrect.")

    analyze_button = ctk.CTkButton(root, text="Analyze", command=analyze_file)
    analyze_button.pack(pady=20)

    plugin_dropdown = ctk.CTkOptionMenu(root, values=plugins, width=120, height=25, corner_radius=10)
    if plugins:
        plugin_dropdown.set(plugins[0])  # Automatically select the first plugin in the list
    plugin_dropdown.pack(pady=10)

