# analyzebutton.py
import customtkinter as ctk
import os

def create_analysis_widgets(root, get_file_path):
    def analyze_file():
        file_path = get_file_path()
        if file_path and os.path.exists(file_path):
            print("Analyzing:", file_path)
            # Your file analysis logic goes here
            # For example, read the file or process its data
            try:
                with open(file_path, 'r') as file:
                    data = file.read()
                    print("File contents:", data[:100])  # Display the first 100 characters
            except Exception as e:
                print("Failed to read the file:", e)
        else:
            print("No file uploaded or file path is incorrect.")

    analyze_button = ctk.CTkButton(root, text="Analyze", command=analyze_file)
    analyze_button.pack(pady=20)
