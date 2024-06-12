import customtkinter as ctk
from tkinter import filedialog, StringVar
import os
from volatility3.framework import contexts, constants
from volatility3 import framework, plugins


def select_file(self):
    file_path = filedialog.askopenfilename(
        title="Select a Memory Dump File",
        filetypes=[("Memory dump files", "*.vmem;*.dmp;*.img;*.bin;*.mem"), ("All files", "*.*")],
        initialdir=os.path.expanduser("~")  # Start at the user's home directory for better cross-platform compatibility
    )
    if file_path:
        self.file_path_var.set(file_path)
        self.update_plugin_dropdown(file_path)


def create_plugin_dropdown(self, plugins, master):
    if self.plugin_dropdown:
        self.plugin_dropdown.destroy()
    self.plugin_dropdown = ctk.CTkOptionMenu(
        master=master, variable=self.plugin_dropdown_var, values=plugins, fg_color=self.input_field_color,
        text_color=self.text_bright, button_color=self.button_color, button_hover_color=self.header_color,
        font=self.font, width=200
    )
    self.plugin_dropdown.pack(side="top", pady=(0, 10), anchor="center")


def update_plugin_dropdown(self, file_path):
    plugins = self.get_volatility_plugins()
    categorized_plugins = self.categorize_plugins(plugins)
    self.create_plugin_dropdown(["Load file to select plugin"] + categorized_plugins, master=self.dropdown_frame)
    self.plugin_dropdown_var.set("Select plugin")


def get_volatility_plugins(self):
    # Create a new context
    context = contexts.Context()

    # Ensure we use the correct version of the volatility framework
    framework.require_interface_version(2, 7, 0)

    # Load the plugins
    plugins.__path__ = constants.PLUGINS_PATH
    failures = framework.import_files(plugins, True)

    if failures:
        print(f"Plugin import failures: {failures}")

    # Get the list of plugins
    plugin_list = framework.list_plugins()

    return list(plugin_list.keys())


def categorize_plugins(self, plugins):
    categories = {
        "Windows": [],
        "Linux": [],
        "Mac": [],
        "Other": []
    }
    for plugin in plugins:
        if plugin.startswith("windows"):
            categories["Windows"].append(plugin)
        elif plugin.startswith("linux"):
            categories["Linux"].append(plugin)
        elif plugin.startswith("mac"):
            categories["Mac"].append(plugin)
        else:
            categories["Other"].append(plugin)

    categorized_plugins = []
    for category, plugin_list in categories.items():
        categorized_plugins.append(f"{category} Plugins:")
        categorized_plugins.extend(plugin_list)

    return categorized_plugins
