import customtkinter as ctk
from tkinter import filedialog, Toplevel, StringVar, messagebox, Text, Scrollbar
import tkinter as tk
import os
import subprocess
import threading
import json
from volatility3.framework import contexts, automagic, constants
from volatility3 import framework, plugins
from tkinter import ttk


# Configuration file path
CONFIG_FILE = "config.json"


def load_volatility_path():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
            return config.get("VOLATILITY_PATH", None)
    return None


def save_volatility_path(path):
    config = {"VOLATILITY_PATH": path}
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)


def prompt_for_volatility_path():
    path = filedialog.askopenfilename(
        title="Select Volatility 3 Script",
        filetypes=[("Python files", "*.py"), ("All files", "*.*")]
    )
    if path:
        save_volatility_path(path)
        return path
    return None


def get_volatility_path():
    path = load_volatility_path()
    if not path or not os.path.exists(path):
        messagebox.showinfo("Volatility Path Not Found", "Please select the Volatility 3 vol.py script.")
        path = prompt_for_volatility_path()
        if not path:
            messagebox.showerror("Path Selection Error", "Volatility path not set. The application will exit.")
            exit()
    return path


class VolatilityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Volatility 3 Analysis Tool")
        self.geometry("900x700")
        self.tab_names = set()


        # Colors and font styling from design template
        self.background_color = "#262626"
        self.header_color = "#222222"
        self.button_color = "#A9DFD8"
        self.textbox_color = "#647A77"
        self.input_field_color = "#474747"
        self.text_bright = "#F5F5F5"
        self.text_dark = "#000000"
        self.font = ("Arial", 14)

        # Configure root window
        self.configure(bg=self.background_color)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6, 7], weight=1)

        # Path variable to store the selected file path
        self.file_path_var = StringVar(value="No file selected")

        # Plugin dropdown variable
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")

        # Renderer dropdown variable
        self.renderer_var = StringVar(value="quick")

        # Verbose option variable
        self.verbose_var = ctk.BooleanVar(value=False)

        # Initial plugin dropdown as None
        self.plugin_dropdown = None

        # Tabview for results
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=8, column=0, padx=20, pady=20, sticky="nsew")
        self.tab_names = set()

        # Header
        header = ctk.CTkLabel(self, text="File Analysis", font=("Arial", 24, "bold"), text_color=self.text_bright,
                              bg_color=self.background_color)
        header.grid(row=0, column=0, padx=20, pady=20)

        # File Selection Button
        file_button = ctk.CTkButton(self, text="Select File", command=self.select_file, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color=self.header_color, font=self.font)
        file_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        # File Path Label
        file_label = ctk.CTkLabel(self, textvariable=self.file_path_var, font=self.font, text_color=self.text_bright,
                                  bg_color=self.background_color)
        file_label.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        # Plugin Dropdown
        self.create_plugin_dropdown(["Load file to select plugin"])

        # Renderer Option
        renderer_dropdown = ctk.CTkOptionMenu(
            self, variable=self.renderer_var, values=["quick", "pretty", "json", "csv"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font
        )
        renderer_dropdown.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        # Verbose Option
        verbose_checkbox = ctk.CTkCheckBox(
            self, text="Verbose", variable=self.verbose_var, onvalue=True, offvalue=False,
            fg_color=self.input_field_color, text_color=self.text_bright, font=self.font
        )
        verbose_checkbox.grid(row=5, column=0, padx=20, pady=10, sticky="w")

        # Analyze Button
        analyze_button = ctk.CTkButton(self, text="Analyze", command=self.run_analysis, fg_color=self.button_color,
                                       text_color=self.text_dark, hover_color=self.header_color, font=self.font)
        analyze_button.grid(row=6, column=0, padx=20, pady=20, sticky="ew")

        # Load and set the Volatility path
        self.VOLATILITY_PATH = get_volatility_path()

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a Memory Dump File",
            filetypes=[("Memory dump files", "*.vmem;*.dmp;*.img;*.bin;*.mem"), ("All files", "*.*")],
            initialdir=os.getcwd()
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.update_plugin_dropdown(file_path)

    def create_plugin_dropdown(self, plugins):
        if self.plugin_dropdown:
            self.plugin_dropdown.destroy()
        self.plugin_dropdown = ctk.CTkOptionMenu(
            self, variable=self.plugin_dropdown_var, values=plugins, fg_color=self.input_field_color,
            text_color=self.text_bright, button_color=self.button_color, button_hover_color=self.header_color,
            font=self.font
        )
        self.plugin_dropdown.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

    def update_plugin_dropdown(self, file_path):
        plugins = self.get_volatility_plugins()
        categorized_plugins = self.categorize_plugins(plugins)
        self.create_plugin_dropdown(["Select plugin"] + categorized_plugins)
        self.plugin_dropdown_var.set("Select plugin")

    def get_volatility_plugins(self):
        # Create a new context
        context = contexts.Context()

        # Ensure we use the correct version of the volatility framework
        framework.require_interface_version(2, 0, 0)

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

    def run_analysis(self):
        file_path = self.file_path_var.get()
        selected_plugin = self.plugin_dropdown_var.get()
        renderer = self.renderer_var.get()
        verbose = self.verbose_var.get()

        if selected_plugin == "Select plugin" or selected_plugin == "Load file to select plugin":
            messagebox.showwarning("Invalid Selection", "Please select a valid plugin.")
            return
        if file_path and os.path.exists(file_path):
            self.show_progress_modal(file_path, selected_plugin, renderer, verbose)
        else:
            messagebox.showwarning("Invalid File", "Please select a valid file.")

    def show_progress_modal(self, file_path, plugin, renderer, verbose):
        modal = Toplevel(self)
        modal.title("Analyzing...")
        modal.geometry("400x150")
        modal.configure(bg="#262626")
        modal.transient(self)
        modal.grab_set()

        progress_var = StringVar()
        progress_var.set("0%")

        progress_bar = ctk.CTkProgressBar(modal, mode='indeterminate', fg_color="#A9DFD8")
        progress_bar.pack(pady=10, padx=20, fill='x')
        progress_bar.start()

        progress_label = ctk.CTkLabel(modal, textvariable=progress_var, font=("Arial", 14), text_color="#F5F5F5",
                                      bg_color="#262626")
        progress_label.pack(pady=10)

        threading.Thread(target=self.execute_volatility,
                         args=(file_path, plugin, renderer, verbose, modal, progress_bar, progress_var)).start()

    def execute_volatility(self, file_path, plugin, renderer, verbose, modal, progress_bar, progress_var):
        command = ["python", self.VOLATILITY_PATH, "-r", renderer]
        if verbose:
            command.append("-v")
        command.extend(["-f", file_path, plugin])

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                content = stdout
                self.create_result_tab(plugin, renderer, content)
            else:
                self.create_result_tab(plugin, renderer, f"Error: {stderr}")
        except Exception as e:
            self.create_result_tab(plugin, renderer, str(e))
        finally:
            progress_bar.stop()
            progress_var.set("100%")
            modal.grab_release()
            modal.destroy()

    def create_result_tab(self, plugin, renderer, content):
        tab_name = f"Result - {plugin} ({renderer})"
        if tab_name in self.tab_names:
            self.tabview.delete(tab_name)  # Remove the existing tab with the same name
            self.tab_names.remove(tab_name)

        tab_frame = self.tabview.add(tab_name)
        self.tab_names.add(tab_name)  # Add the new tab name to the set

        close_button = ctk.CTkButton(tab_frame, text="Close Tab", command=lambda: self.close_tab(tab_name),
                                     fg_color=self.button_color, text_color=self.text_dark,
                                     hover_color=self.header_color, font=self.font)
        close_button.pack(pady=10)

        lines = content.splitlines()
        if not lines:
            return

        # Extract headers properly
        headers = lines[0].split()
        # Filter out empty strings and extra spaces
        headers = [header for header in headers if header.strip()]

        tree = ttk.Treeview(tab_frame, columns=headers, show="headings")

        # Configure headings dynamically
        for header in headers:
            tree.heading(header, text=header)

        # Style the Treeview
        style = ttk.Style()
        style.configure("Treeview",
                        background="#262626",  # Background
                        foreground="#F5F5F5",  # Text bright
                        fieldbackground="#262626",
                        rowheight=25,
                        font=("Arial", 14))

        style.configure("Treeview.Heading",
                        background="#222222",  # Dark background for header
                        foreground="#222222",  # Dark text for header
                        font=("Arial", 14, "bold"))

        style.map("Treeview",
                  background=[('selected', '#474747')],  # Boxes/input-fields
                  foreground=[('selected', '#F5F5F5')])  # Text bright

        # Make the Treeview headers have a consistent dark background
        style.layout("Treeview.Heading", [
            ('Treeheading.cell', {'sticky': 'nswe'}),
            ('Treeheading.border', {'sticky': 'nswe', 'children': [
                ('Treeheading.padding', {'sticky': 'nswe', 'children': [
                    ('Treeheading.image', {'side': 'right', 'sticky': ''}),
                    ('Treeheading.text', {'sticky': 'we'})
                ]})
            ]})
        ])

        # Insert data into the Treeview
        for line in lines[1:]:  # Skip the header line
            values = line.split()
            values = [value for value in values if value.strip()]  # Filter out empty strings and extra spaces
            tree.insert("", "end", values=values)

        tree.pack(padx=10, pady=10, fill='both', expand=True)
        self.tabview.set(tab_name)

    def close_tab(self, tab_name):
        self.tabview.delete(tab_name)
        self.tab_names.remove(tab_name)



if __name__ == "__main__":
    app = VolatilityApp()
    app.mainloop()
