import customtkinter as ctk
from tkinter import filedialog, StringVar, messagebox, Text
import os
import time
import subprocess
import threading
import json
import logging
from volatility3.framework import contexts, constants
from volatility3 import framework, plugins
from tkinter import ttk

# Configuration file path
CONFIG_FILE = "config.json"
LOG_FILE = "app.log"

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


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
        self.geometry("900x900")
        self.setup_ui()
        self.tab_names = set()  # Initialize tab_names attribute
        self.load_settings()  # Load saved settings

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
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6, 7, 8], weight=1)


        # Path variable to store the selected file path
        self.file_path_var = StringVar(value="No file selected")

        # Plugin dropdown variable
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")

        # Renderer dropdown variable
        self.renderer_var = StringVar(value="none")

        # Verbose option variable
        self.verbose_var = ctk.BooleanVar(value=False)

        # Initial plugin dropdown as None
        self.plugin_dropdown = None

        # Tabview for results
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=8, column=0, columnspan=2, padx=20, pady=20, sticky="ew")

        # Header
        header = ctk.CTkLabel(self, text="File Analysis", font=("Arial", 24, "bold"), text_color=self.text_bright,
                              bg_color=self.background_color)
        header.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="n")

        # File Selection Button
        file_button = ctk.CTkButton(self, text="Select File", command=self.select_file, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=150)
        file_button.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # File Path Label
        file_label = ctk.CTkLabel(self, textvariable=self.file_path_var, font=self.font, text_color=self.text_bright,
                                  bg_color=self.background_color)
        file_label.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # Create a frame for dropdowns
        self.dropdown_frame = ctk.CTkFrame(self, fg_color=self.background_color)
        self.dropdown_frame.grid(row=3, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # Plugin Dropdown
        self.create_plugin_dropdown(["Load file to select plugin"], master=self.dropdown_frame)

        # Renderer Option
        renderer_dropdown = ctk.CTkOptionMenu(
            master=self.dropdown_frame, variable=self.renderer_var, values=["none", "quick", "pretty", "json"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font, width=200
        )
        renderer_dropdown.pack(side="left", padx=(0, 20))

        # Verbose Option
        verbose_checkbox = ctk.CTkCheckBox(
            self, text="Verbose", variable=self.verbose_var, onvalue=True, offvalue=False,
            fg_color=self.input_field_color, text_color=self.text_bright, font=self.font
        )
        verbose_checkbox.grid(row=4, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # Analyze Button
        analyze_button = ctk.CTkButton(self, text="Analyze", command=self.run_analysis, fg_color=self.button_color,
                                       text_color=self.text_dark, hover_color="#5A9", font=self.font, width=150)
        analyze_button.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # Help Button
        help_button = ctk.CTkButton(self, text="Help", command=self.show_help, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=150)
        help_button.grid(row=8, column=1, padx=20, pady=10, sticky="se")

        # Add a Settings Button
        settings_button = ctk.CTkButton(self, text="Settings", command=self.show_settings_window,
                                        fg_color=self.button_color,
                                        text_color=self.text_dark, hover_color="#5A9", font=self.font, width=150)
        settings_button.grid(row=7, column=1, padx=20, pady=10, sticky="se")

        # Load and set the Volatility path
        self.VOLATILITY_PATH = get_volatility_path()

    def setup_ui(self):
        self.file_path_var = StringVar(value="No file selected")
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")
        self.verbose_var = ctk.BooleanVar(value=False)
        self.renderer_var = StringVar(value="none")

        def change_theme(self, new_theme):
            ctk.set_appearance_mode(new_theme.lower())

    def load_settings(self):
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as settings_file:
                settings = json.load(settings_file)
                self.renderer_var.set(settings.get("renderer", "none"))
                self.verbose_var.set(settings.get("verbose", False))

    def save_volatility_path(self, path):
        save_volatility_path(path)
        self.VOLATILITY_PATH = path
        messagebox.showinfo("Settings", "Volatility 3 path saved successfully.")

    def save_settings(self, renderer, verbose):
        settings = {
            "renderer": renderer,
            "verbose": verbose
        }
        with open("settings.json", "w") as settings_file:
            json.dump(settings, settings_file)
        messagebox.showinfo("Settings", "Settings saved successfully.")
    def show_help(self):
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

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a Memory Dump File",
            filetypes=[("Memory dump files", "*.vmem;*.dmp;*.img;*.bin;*.mem"), ("All files", "*.*")],
            initialdir=os.getcwd()
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
        self.plugin_dropdown.pack(side="left", padx=(0, 20))  # Ensure spacing is maintained

    def update_plugin_dropdown(self, file_path):
        plugins = self.get_volatility_plugins()
        categorized_plugins = self.categorize_plugins(plugins)
        self.create_plugin_dropdown(["Load file to select plugin"] + categorized_plugins, master=self.dropdown_frame)
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
        # Create a frame to act as a modal
        self.modal_frame = ctk.CTkFrame(self, fg_color="#333333", corner_radius=10)
        self.modal_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.5, relheight=0.25)

        header_label = ctk.CTkLabel(self.modal_frame, text="Analyzing...", font=("Arial", 18, "bold"), text_color="#FFFFFF")
        header_label.pack(pady=10)

        progress_var = StringVar()
        progress_var.set("0%")

        progress_bar = ctk.CTkProgressBar(self.modal_frame, fg_color="#00BCD4", mode='determinate')
        progress_bar.pack(pady=10, padx=20, fill='x')
        progress_bar.set(0)

        progress_label = ctk.CTkLabel(self.modal_frame, textvariable=progress_var, font=("Arial", 14), text_color="#FFFFFF")
        progress_label.pack(pady=10)

        # Start the animation thread
        threading.Thread(target=self.animate_progress_bar, args=(progress_bar, progress_var)).start()
        # Start the volatility execution thread
        threading.Thread(target=self.execute_volatility,
                         args=(file_path, plugin, renderer, verbose, progress_bar, progress_var)).start()

    def animate_progress_bar(self, progress_bar, progress_var):
        for i in range(101):
            time.sleep(1.2)
            progress_var.set(f"{i}%")
            progress_bar.set(i / 100)
            self.update_idletasks()

    def execute_volatility(self, file_path, plugin, renderer, verbose, progress_bar, progress_var):
        command = ["python", self.VOLATILITY_PATH, "-r", renderer]
        if verbose:
            command.append("-v")
        command.extend(["-f", file_path, plugin])

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            total_steps = 100  # Total steps for progress bar simulation
            for step in range(total_steps):
                time.sleep(0.1)  # Simulate work being done
                progress = (step + 1) / total_steps
                progress_var.set(f"{int(progress * 100)}%")
                progress_bar.set(progress)
                self.update_idletasks()

            stdout, stderr = process.communicate()
            if process.returncode == 0:
                content = stdout
                self.create_result_tab(plugin, renderer, content)
            else:
                self.create_result_tab(plugin, renderer, f"Error: {stderr}")
        except Exception as e:
            self.create_result_tab(plugin, renderer, str(e))
            logging.error(f"Error executing Volatility plugin: {e}")
        finally:
            progress_bar.set(1)
            progress_var.set("100%")
            self.after(500, self.remove_progress_modal)

    def remove_progress_modal(self):
        self.modal_frame.destroy()

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

        if "info" in plugin.lower():
            # For "info" plugins, display content in a Text widget
            self.display_info_content(tab_frame, content)
        else:
            # For other plugins, display content in a Treeview
            self.display_treeview_content(tab_frame, content)

        self.tabview.set(tab_name)

    def display_info_content(self, tab_frame, content):
        text_widget = Text(tab_frame, wrap="word", bg="#262626", fg="#F5F5F5", font=("Arial", 14), padx=10, pady=10)
        text_widget.insert("1.0", content)
        text_widget.pack(padx=10, pady=10, fill='both', expand=True)

    def display_treeview_content(self, tab_frame, content):
        lines = content.splitlines()
        if not lines:
            return

        headers = lines[0].split()
        headers = [header for header in headers if header.strip()]

        tree = ttk.Treeview(tab_frame, columns=headers, show="headings")

        for header in headers:
            tree.heading(header, text=header)

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

        style.layout("Treeview.Heading", [
            ('Treeheading.cell', {'sticky': 'nswe'}),
            ('Treeheading.border', {'sticky': 'nswe', 'children': [
                ('Treeheading.padding', {'sticky': 'nswe', 'children': [
                    ('Treeheading.image', {'side': 'right', 'sticky': ''}),
                    ('Treeheading.text', {'sticky': 'we'})
                ]})
            ]})
        ])

        for line in lines[2:]:  # Skip the header line
            values = line.split()
            values = [value for value in values if value.strip()]
            tree.insert("", "end", values=values)

        tree.pack(padx=10, pady=10, fill='both', expand=True)

    def close_tab(self, tab_name):
        self.tabview.delete(tab_name)
        self.tab_names.remove(tab_name)

    def close_settings_modal(self):
        self.settings_modal.destroy()

    def change_theme(self, new_theme):
        if new_theme.lower() == "light":
            self.background_color = "#F3EDE4"
            self.header_color = "#D8D2CB"
            self.button_color = "#C5BEB4"
            self.textbox_color = "#EDE6DE"
            self.input_field_color = "#D0C7BF"
            self.text_bright = "#4B4A47"
            self.text_dark = "#FFFFFF"
        else:
            # Default to dark theme
            self.background_color = "#262626"
            self.header_color = "#222222"
            self.button_color = "#A9DFD8"
            self.textbox_color = "#647A77"
            self.input_field_color = "#474747"
            self.text_bright = "#F5F5F5"
            self.text_dark = "#000000"

        self.apply_theme()

    def apply_theme(self):
        self.configure(bg=self.background_color)
        self.tabview.configure(fg_color=self.background_color)

        # Update all widgets with the new theme
        for widget in self.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                widget.configure(fg_color=self.background_color)
            elif isinstance(widget, ctk.CTkLabel):
                widget.configure(text_color=self.text_bright, bg_color=self.background_color)
            elif isinstance(widget, ctk.CTkButton):
                widget.configure(fg_color=self.button_color, text_color=self.text_dark, hover_color=self.header_color)
            elif isinstance(widget, ctk.CTkOptionMenu):
                widget.configure(fg_color=self.input_field_color, text_color=self.text_bright,
                                 button_color=self.button_color, button_hover_color=self.header_color)
            elif isinstance(widget, ctk.CTkCheckBox):
                widget.configure(fg_color=self.input_field_color, text_color=self.text_bright)

    def show_settings_window(self):
        self.settings_modal = ctk.CTkFrame(self, fg_color="#333333", corner_radius=10)
        self.settings_modal.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

        header_label = ctk.CTkLabel(self.settings_modal, text="Settings", font=("Arial", 18, "bold"),
                                    text_color="#FFFFFF")
        header_label.pack(pady=10)

        # Example settings: theme selection
        theme_label = ctk.CTkLabel(self.settings_modal, text="Select Theme:", font=self.font, text_color="#FFFFFF")
        theme_label.pack(pady=10)

        theme_option = ctk.CTkOptionMenu(self.settings_modal, values=["Light", "Dark", "System"],
                                         command=self.change_theme)
        theme_option.pack(pady=10)

        # Add settings for Volatility 3 path
        volatility_path_label = ctk.CTkLabel(self.settings_modal, text="Volatility 3 Path:", font=self.font,
                                             text_color="#FFFFFF")
        volatility_path_label.pack(pady=10)

        volatility_path_entry = ctk.CTkEntry(self.settings_modal, width=300)
        volatility_path_entry.insert(0, self.VOLATILITY_PATH)
        volatility_path_entry.pack(pady=10)

        save_path_button = ctk.CTkButton(self.settings_modal, text="Save Path",
                                         command=lambda: self.save_volatility_path(volatility_path_entry.get()))
        save_path_button.pack(pady=10)

        # Add settings for default renderer
        renderer_label = ctk.CTkLabel(self.settings_modal, text="Default Renderer:", font=self.font,
                                      text_color="#FFFFFF")
        renderer_label.pack(pady=10)

        renderer_option = ctk.CTkOptionMenu(self.settings_modal, variable=self.renderer_var,
                                            values=["none", "quick", "pretty", "json"])
        renderer_option.pack(pady=10)

        # Add settings for default verbosity
        verbose_label = ctk.CTkLabel(self.settings_modal, text="Verbose Mode:", font=self.font, text_color="#FFFFFF")
        verbose_label.pack(pady=10)

        verbose_option = ctk.CTkCheckBox(self.settings_modal, text="Enable", variable=self.verbose_var, onvalue=True,
                                         offvalue=False)
        verbose_option.pack(pady=10)

        save_settings_button = ctk.CTkButton(self.settings_modal, text="Save Settings",
                                             command=lambda: self.save_settings(renderer_option.get(),
                                                                                self.verbose_var.get()))
        save_settings_button.pack(pady=10)

        close_button = ctk.CTkButton(self.settings_modal, text="Close", command=self.close_settings_modal,
                                     fg_color=self.button_color, text_color=self.text_dark,
                                     hover_color=self.header_color, font=self.font)
        close_button.pack(pady=10)


