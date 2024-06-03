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
VOLATILITY_PATH = r'C:\Users\Kaiwa\volatility3-develop'




class VolatilityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Volatility 3 Analysis Tool")
        self.geometry("900x700")
        self.setup_ui()
        self.tab_names = set()  # Initialize tab_names attribute

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
        self.renderer_var = StringVar(value="none")

        # Verbose option variable
        self.verbose_var = ctk.BooleanVar(value=False)

        # Initial plugin dropdown as None
        self.plugin_dropdown = None

        # Tabview for results
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=8, column=0, padx=20, pady=20, sticky="nsew")

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

        # Create a frame for dropdowns
        self.dropdown_frame = ctk.CTkFrame(self, fg_color=self.background_color)
        self.dropdown_frame.grid(row=3, column=0, padx=20, pady=10)

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
        verbose_checkbox.grid(row=5, column=0, padx=20, pady=10, sticky="w")

        # Analyze Button
        analyze_button = ctk.CTkButton(self, text="Analyze", command=self.run_analysis, fg_color=self.button_color,
                                       text_color=self.text_dark, hover_color=self.header_color, font=self.font)
        analyze_button.grid(row=6, column=0, padx=20, pady=20, sticky="ew")

        # Help Button
        help_button = ctk.CTkButton(self, text="Help", command=self.show_help, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color=self.header_color, font=self.font)
        help_button.grid(row=7, column=0, padx=20, pady=10, sticky="ew")

        # Load and set the Volatility path
        self.VOLATILITY_PATH = get_volatility_path()

    def setup_ui(self):
        self.file_path_var = StringVar(value="No file selected")
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")
        self.verbose_var = ctk.BooleanVar(value=False)
        self.renderer_var = StringVar(value="none")

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
            time.sleep(0.02)
            progress_var.set(f"{i}%")
            progress_bar.set(i / 100)
            self.update_idletasks()

    def execute_volatility(self, file_path, plugin, renderer, verbose, progress_bar, progress_var):
        command = ["python", self.VOLATILITY_PATH, "-r", renderer]
        if verbose:
            command.append("-v")
        command.extend(["-f", file_path, plugin])

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        try:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    # Parse the output to extract progress information
                    if "Progress" in output:
                        parts = output.strip().split(" - ")
                        if len(parts) == 2:
                            progress = parts[0].split(" ")[1]
                            status = parts[1]
                            progress_var.set(progress)
                            progress_bar.set(int(progress.strip('%')) / 100)
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


if __name__ == "__main__":
    app = VolatilityApp()
    app.mainloop()
