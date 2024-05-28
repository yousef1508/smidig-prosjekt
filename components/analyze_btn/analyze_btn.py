import tkinter as tk
from tkinter import ttk

def analyze(uploaded_file):
    """This function is executed when the 'Analyze' button is clicked."""
    if uploaded_file:
        print(f"Analyzing file: {uploaded_file}")
        # Add the analysis logic here
    else:
        print("No file uploaded.")

def on_enter(event):
    event.widget.config(bg="#c3e4ed")  # Change to a lighter color to simulate glow

def on_leave(event):
    event.widget.config(bg="#A9DFD8")  # Restore original color

def on_click(event):
    event.widget.config(bg="white", fg="black")  # Change color to white on click

def create_analysis_widgets(parent, get_uploaded_file):
    """Create and place the Combobox and Analyze button into the given parent widget."""
    # Style for Combobox and button
    style = ttk.Style()
    style.theme_use('clam')
    style.configure(
        "TCombobox",
        fieldbackground='#1C1C1C',
        background='#1C1C1C',
        foreground='white',
        font=('Roboto', 12)
    )
    style.map(
        "TCombobox",
        fieldbackground=[('readonly', '#1C1C1C')],
        selectbackground=[('readonly', '#1C1C1C')],
        selectforeground=[('readonly', 'white')]
    )
    style.configure(
        "TButton",
        background='#A7E4D8',
        foreground='black',
        font=('Roboto', 12, 'bold')
    )

    # Add a Drop-down (Combobox) for Plugin
    plugin_combobox = ttk.Combobox(
        parent,
        values=[
            "Plugin 1", "Plugin 2", "Plugin 3", "Plugin 4", "Plugin 5",
            "Plugin 6", "Plugin 7", "Plugin 8", "Plugin 9", "Plugin 10",
            "Plugin 11", "Plugin 12", "Plugin 13"
        ],
        style="TCombobox",
        state="readonly"
    )
    plugin_combobox.set("Choose Plug-in")
    plugin_combobox.config(width=25)  # Adjust the width of the combobox
    plugin_combobox.pack(pady=10)  # Place the combobox in the parent with padding

    # Add the "Analyze" button
    analyze_button = tk.Button(
        parent,
        text="ANALYZE",
        command=lambda: analyze(get_uploaded_file()),  # Pass the uploaded file to the analyze function
        bg='#A9DFD8',
        fg='black',
        font=('Roboto', 12, 'bold'),
        relief=tk.FLAT,  # Make the button flat
        borderwidth=0,  # Remove the border
        padx=10,  # Add padding for better look
        pady=10
    )
    analyze_button.config(width=20, height=1)  # Adjust the size of the button
    analyze_button.pack(pady=20)  # Place the button in the parent with padding

    # Bind mouse events
    analyze_button.bind("<Enter>", on_enter)
    analyze_button.bind("<Leave>", on_leave)
    analyze_button.bind("<Button-1>", on_click)  # Binds the left mouse click

    return plugin_combobox, analyze_button