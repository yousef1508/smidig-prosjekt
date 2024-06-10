# helpers.py
from tkinter import messagebox

def show_help():
    help_text = """
    Welcome to the Volatility 3 Analysis Tool!

    1. Select a memory dump file.
    2. Choose a plugin from the dropdown.
    3. Choose a renderer option.
    4. Click 'Analyze' to run the analysis.
    5. View the results in the tabbed interface.

    For more information, refer to the official Volatility 3 documentation.
    """
    messagebox.showinfo("Help", help_text)
