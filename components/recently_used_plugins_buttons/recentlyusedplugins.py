import customtkinter as ctk

# Main window
root = ctk.CTk()
root.title("Plugin Display Example")
root.geometry("500x300")

# Configure grid layout for the main window
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Function for plugins frame
def create_plugins_frame(root):
    # Create a frame for the plugins section
    frame = ctk.CTkFrame(root, corner_radius=10, fg_color="#1e1e1e")
    frame.grid(column=0, row=0, padx=20, pady=20, sticky="nsew")

    # Label for Recently used plug-ins
    label = ctk.CTkLabel(frame, text="Recently used plug-ins", text_color="white", font=("Arial", 16))
    label.grid(column=0, row=0, columnspan=3, pady=10)

    # Grid layout for the frame
    frame.columnconfigure((0, 1, 2), weight=1, uniform="column")
    frame.rowconfigure(1, weight=1, uniform="row")

    # List of Volatility 3 plugins
    plugin_names = [
        "windows.info",
        "windows.pslist",
        "windows.netstat"
    ]

    # Plugin labels
    for i, plugin_name in enumerate(plugin_names):
        col = i % 3  # Determine column index (0, 1, or 2)
        label = ctk.CTkLabel(
            frame,
            text=plugin_name,  # This should be replaced with an image in actual implementation
            fg_color="#2e2e2e",
            text_color="white",
            width=100,
            height=50,
            corner_radius=8
        )
        label.grid(column=col, row=1, padx=10, pady=10, sticky="nsew")

    return frame

# Create and center the plugins frame in the main window
create_plugins_frame(root)

# Run the application
root.mainloop()
