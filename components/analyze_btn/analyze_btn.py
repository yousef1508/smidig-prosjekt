import customtkinter as ctk
import os

def create_analysis_widgets(root, get_file_path):
    # Adjust the path to point to the 'plugins' directory at the root of your project
    plugin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'plugins')
    # List all Python files in the directory as potential plugins
    plugins = [plugin for plugin in os.listdir(plugin_dir) if plugin.endswith('.py')]

    # Function to handle file analysis using the selected plugin
    def analyze_file():
        file_path = get_file_path()
        selected_plugin = plugin_dropdown.get()
        if file_path and os.path.exists(file_path):
            print(f"Analyzing: {file_path} using {selected_plugin}")
            try:
                with open(file_path, 'r') as file:
                    data = file.read()
                    print("File contents:", data[:100])  # Show the first 100 characters of the file
                    # Future implementation: Dynamically import and use the selected plugin
            except Exception as e:
                print("Failed to read the file:", e)
        else:
            print("No file uploaded or file path is incorrect.")

    # Create the 'Analyze' button
    analyze_button = ctk.CTkButton(root, text="Analyze", command=analyze_file)
    analyze_button.pack(pady=20)

    # Create a dropdown menu for selecting a plugin
    plugin_dropdown = ctk.CTkOptionMenu(root, values=plugins, width=120, height=25, corner_radius=10)
    if plugins:
        plugin_dropdown.set(plugins[0])  # Automatically select the first plugin in the list
    plugin_dropdown.pack(pady=10)
