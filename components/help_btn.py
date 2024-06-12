from tkinter import messagebox

def show_help():
    help_text = """
Welcome to the Volatility 3 Analysis Tool!

Steps to use the tool:
1. Select a memory dump file by clicking the 'Select File' button.

2. Choose a plugin from the plugin dropdown (this will be populated after selecting a file).

3. Choose a renderer option ('quick' or 'pretty').

4. Optionally, select the 'Verbose' checkbox for detailed output.

5. Click 'Analyze' to run the analysis.

6. View the results in the tabbed interface at the bottom.

Additional Features:
- Settings: Configure the path to Volatility 3 executable.
- Help: Display this help message.
- Export: Save the analysis results to a file (CSV or PDF).
- Search: Search for specific text within the analysis results.
- Expand: Expand or collapse the view area of the analysis results.

For more information, refer to the official Volatility 3 documentation.
    """
    messagebox.showinfo("Help", help_text)
