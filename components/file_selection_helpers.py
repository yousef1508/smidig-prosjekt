# Import necessary modules
import customtkinter as ctk  # For creating custom Tkinter widgets
from tkinter import filedialog, StringVar  # For file dialogs and string variable handling
import os  # For operating system related functionalities
from volatility3.framework import contexts, constants  # For Volatility framework contexts and constants
from volatility3 import framework, plugins  # For Volatility framework and plugins

def select_file(self):
    """
    Opens a file dialog for the user to select a memory dump file and updates the file path variable.
    """
    file_path = filedialog.askopenfilename(
        title="Select a Memory Dump File",
        filetypes=[("Memory dump files", "*.vmem;*.dmp;*.img;*.bin;*.mem"), ("All files", "*.*")],  # Filter for memory dump files
        initialdir=os.path.expanduser("~")  # Start at the user's home directory for better cross-platform compatibility
    )
    if file_path:
        self.file_path_var.set(file_path)  # Update the file path variable
        self.update_plugin_dropdown(file_path)  # Update the plugin dropdown based on the selected file

def create_plugin_dropdown(self, plugins, master):
    """
    Creates a dropdown menu for selecting a plugin from the available plugins.

    :param plugins: List of available plugins to populate the dropdown.
    :param master: The master widget to attach the dropdown menu.
    """
    if self.plugin_dropdown:
        self.plugin_dropdown.destroy()  # Destroy existing dropdown if it exists
    # Create a new dropdown menu with the given plugins
    self.plugin_dropdown = ctk.CTkOptionMenu(
        master=master, variable=self.plugin_dropdown_var, values=plugins,
        fg_color=self.input_field_color, text_color=self.text_bright,
        button_color=self.button_color, button_hover_color=self.header_color,
        font=self.font, width=200
    )
    self.plugin_dropdown.pack(side="top", pady=(0, 10), anchor="center")  # Pack the dropdown in the master widget

def update_plugin_dropdown(self, file_path):
    """
    Updates the plugin dropdown menu based on the selected file path.

    :param file_path: The path of the selected memory dump file.
    """
    plugins = self.get_volatility_plugins()  # Retrieve the list of Volatility plugins
    categorized_plugins = self.categorize_plugins(plugins)  # Categorize the plugins
    # Create and update the dropdown menu with categorized plugins
    self.create_plugin_dropdown(["Load file to select plugin"] + categorized_plugins, master=self.dropdown_frame)
    self.plugin_dropdown_var.set("Select plugin")  # Set the default value for the dropdown

def get_volatility_plugins(self):
    """
    Retrieves a list of available Volatility plugins.

    :return: List of Volatility plugin names.
    """
    # Create a new Volatility context
    context = contexts.Context()

    # Ensure we use the correct version of the Volatility framework
    framework.require_interface_version(2, 7, 0)

    # Load the plugins
    plugins.__path__ = constants.PLUGINS_PATH
    failures = framework.import_files(plugins, True)  # Import plugin files and check for failures

    if failures:
        print(f"Plugin import failures: {failures}")  # Print any plugin import failures

    # Get the list of plugins
    plugin_list = framework.list_plugins()

    return list(plugin_list.keys())  # Return the list of plugin names

def categorize_plugins(self, plugins):
    """
    Categorizes plugins based on the operating system.

    :param plugins: List of plugin names to categorize.
    :return: Categorized list of plugin names.
    """
    # Initialize categories for different operating systems
    categories = {
        "Windows": [],
        "Linux": [],
        "Mac": [],
        "Other": []
    }
    for plugin in plugins:
        if plugin.startswith("windows"):
            categories["Windows"].append(plugin)  # Add to Windows category
        elif plugin.startswith("linux"):
            categories["Linux"].append(plugin)  # Add to Linux category
        elif plugin.startswith("mac"):
            categories["Mac"].append(plugin)  # Add to Mac category
        else:
            categories["Other"].append(plugin)  # Add to Other category

    # Create a categorized list of plugins
    categorized_plugins = []
    for category, plugin_list in categories.items():
        categorized_plugins.append(f"{category} Plugins:")  # Add category header
        categorized_plugins.extend(plugin_list)  # Add plugins under the category

    return categorized_plugins  # Return the categorized list of plugins
