import customtkinter as ctk

def plugin_action(plugin_name):
    """Handles the plugin button click event."""
    print(f'Plugin selected: {plugin_name}')

def create_recently_used_plugins(root):
    # Create a frame for the plugins section
    frame = ctk.CTkFrame(root, corner_radius=10, fg_color="#1e1e1e")
    frame.grid(column=0, row=1, padx=20, pady=20, sticky="nsew")

    # Add a label for "Recently used plug-ins"
    label = ctk.CTkLabel(frame, text="Recently used plug-ins", text_color="white", font=("Arial", 16))
    label.grid(column=0, row=0, columnspan=3, pady=10)

    # Configure grid layout for the frame
    frame.columnconfigure((0, 1, 2), weight=1, uniform="column")
    frame.rowconfigure((1, 2), weight=1, uniform="row")

    # List of Volatility 3 plugins
    plugin_names = [
        "windows.info",
        "windows.pslist",
        "windows.netstat",
        "windows.filescan",
        "windows.hivedump",
        "windows.modules"
    ]

    # Add plugin buttons (boxes)
    for i, plugin_name in enumerate(plugin_names):
        row = 1 + i // 3  # Determine row index (1 or 2, because row 0 is for the label)
        col = i % 3  # Determine column index (0, 1, or 2)
        button = ctk.CTkButton(
            frame,
            text=plugin_name,
            command=lambda p=plugin_name: plugin_action(p),
            fg_color="#2e2e2e",
            text_color="white",
            width=100,
            height=50,
            corner_radius=8
        )
        button.grid(column=col, row=row, padx=10, pady=10, sticky="nsew")

    return frame
