import customtkinter as ctk

def analyze(uploaded_file):
    """This function is executed when the 'Analyze' button is clicked."""
    if uploaded_file:
        print(f"Analyzing file: {uploaded_file}")
        # Add the analysis logic here
    else:
        print("No file uploaded.")

def on_enter(event):
    event.widget.configure(fg_color="#c3e4ed")  # Change to a lighter color to simulate glow

def on_leave(event):
    event.widget.configure(fg_color="#A9DFD8")  # Restore original color

def on_click(event):
    event.widget.configure(fg_color="white", text_color="black")  # Change color to white on click

def create_analysis_widgets(parent, get_uploaded_file):
    """Create and place the Combobox and Analyze button into the given parent widget."""
    # Style for Combobox and button
    ctk.set_default_color_theme("dark-blue")

    # Add a Drop-down (Combobox) for Plugin
    plugin_combobox = ctk.CTkComboBox(
        parent,
        values=[
            "Plugin 1", "Plugin 2", "Plugin 3", "Plugin 4", "Plugin 5",
            "Plugin 6", "Plugin 7", "Plugin 8", "Plugin 9", "Plugin 10",
            "Plugin 11", "Plugin 12", "Plugin 13"
        ],
        width=200,
        height=35,
        font=("Roboto", 12)
    )
    plugin_combobox.set("Choose Plug-in")
    plugin_combobox.pack(pady=10)  # Place the combobox in the parent with padding

    # Add the "Analyze" button
    analyze_button = ctk.CTkButton(
        parent,
        text="ANALYZE",
        command=lambda: analyze(get_uploaded_file()),  # Pass the uploaded file to the analyze function
        fg_color='#A9DFD8',
        text_color='black',
        font=('Roboto', 12, 'bold'),
        width=200,
        height=35
    )
    analyze_button.pack(pady=20)  # Place the button in the parent with padding

    # Bind mouse events
    analyze_button.bind("<Enter>", on_enter)
    analyze_button.bind("<Leave>", on_leave)
    analyze_button.bind("<Button-1>", on_click)  # Binds the left mouse click

    return plugin_combobox, analyze_button
