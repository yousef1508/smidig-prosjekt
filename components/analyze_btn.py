# Import necessary modules
import customtkinter as ctk # For creating custom Tkinter widgets
from tkinter import filedialog, StringVar, messagebox, Text # For file dialogs, string variables, message boxes, and text widgets
import os # For operating system related functionalities
import queue # For handling queues
import time # For time-related functionalities
import subprocess # For running subprocesses
import threading # For handling threads
import logging # For logging
import tkinter as tk # For Tkinter GUI functionalities
import sys # For system-specific parameters and functions
# Import custom modules and functions
from help_btn import show_help
from settings import (
    save_volatility_path,
    get_volatility_path,
    load_settings,
    save_settings,
    show_settings_window,
    change_theme,
    apply_theme
)
from file_selection_helpers import (select_file, create_plugin_dropdown,
                                    update_plugin_dropdown, get_volatility_plugins, categorize_plugins)
from download_btn import save_results_to_file

# Set up logging configuration
LOG_FILE = "app.log"

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def search_text(text_widget, search_var, content):
    """
        Searches for a term in the text widget and highlights matching lines.

        :param text_widget: The text widget to search in.
        :param search_var: The search term.
        :param content: The content of the text widget.
        """
    search_term = search_var.get().lower()
    text_widget.configure(state=tk.NORMAL)  # Enable editing
    text_widget.delete("1.0", tk.END)  # Clear the text widget

    for line in content.splitlines():
        if search_term in line.lower():
            text_widget.insert(tk.END, line + "\n")
    text_widget.configure(state=tk.DISABLED)  # Disable editing


def remove_search(text_widget, content, search_var):
    """
        Removes search highlights and restores the original content.

        :param text_widget: The text widget to restore.
        :param content: The original content of the text widget.
        :param search_var: The search variable to clear.
        """
    search_var.set("")
    text_widget.configure(state=tk.NORMAL)  # Enable editing
    text_widget.delete("1.0", tk.END)  # Clear the text widget

    for line in content.splitlines():
        text_widget.insert(tk.END, line + "\n")
    text_widget.configure(state=tk.DISABLED)  # Disable editing


class VolatilityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.main_window_destroyed = False  # Flag to check if main window is destroyed
        self.title("Volatility 3 Analysis Tool")  # Set window title

        # Load settings
        config = load_settings()
        self.renderer_var = StringVar(value=config.get("renderer", "quick")) # Set renderer variable
        self.verbose_var = ctk.BooleanVar(value=config.get("verbose", False))  # Set verbose variable
        self.VOLATILITY_PATH = config.get("VOLATILITY_PATH", get_volatility_path()) # Set Volatility path

        # UI setup
        self.setup_ui()
        self.tab_names = set() # Set to keep track of tab names
        self.background_color = "#262626"
        self.header_color = "#222222"
        self.button_color = "#A9DFD8"
        self.textbox_color = "#647A77"
        self.input_field_color = "#474747"
        self.text_bright = "#F5F5F5"
        self.text_dark = "#000000"
        self.font = ("Arial", 14) # Set font
        self.configure(bg=self.background_color) # Set background color
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6, 7, 8], weight=1) # Configure grid
        self.file_path_var = StringVar(value="No file selected") # Set file path variable
        self.plugin_dropdown = None # Initialize plugin dropdown
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin") # Set plugin dropdown variable
        # Create tab view
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=8, column=0, columnspan=2, padx=20, pady=20, sticky="ew")
        # Create header label
        header = ctk.CTkLabel(self, text="File Analysis", font=("Arial", 24, "bold"), text_color=self.text_bright,
                              bg_color=self.background_color)
        header.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="n")
        # Create file selection button
        file_button = ctk.CTkButton(self, text="Select File", command=self.select_file, fg_color="#E46F2E",
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=100)
        file_button.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        # Create file label
        file_label = ctk.CTkLabel(self, textvariable=self.file_path_var, font=self.font, text_color=self.text_bright,
                                  bg_color=self.background_color)
        file_label.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        # Create dropdown frame
        self.dropdown_frame = ctk.CTkFrame(self, fg_color=self.background_color)
        self.dropdown_frame.grid(row=3, column=0, columnspan=2, padx=30, pady=10, sticky="n")
        # Create renderer dropdown
        renderer_dropdown = ctk.CTkOptionMenu(
            master=self.dropdown_frame, variable=self.renderer_var, values=["quick", "pretty"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font, width=200
        )
        # Pack the renderer dropdown menu
        renderer_dropdown.pack(side="top", pady=(0, 25), anchor="center")
        # Create the plugin dropdown menu and pack it
        self.plugin_dropdown = ctk.CTkOptionMenu(
            master=self.dropdown_frame, variable=self.plugin_dropdown_var, values=["Load file to select plugin"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font, width=200
        )
        self.plugin_dropdown.pack(side="top", pady=(0, 10), anchor="center")
        # Create the verbose checkbox and place it on the grid
        verbose_checkbox = ctk.CTkCheckBox(
            self, text="Verbose", variable=self.verbose_var, onvalue=True, offvalue=False,
            fg_color=self.input_field_color, text_color=self.text_bright, font=self.font
        )
        verbose_checkbox.grid(row=4, column=0, columnspan=2, padx=20, pady=10, sticky="n")

        # Create the analyze button and place it on the grid
        analyze_button = ctk.CTkButton(self, text="Analyze", command=self.run_analysis, fg_color="#E46F2E",
                                       text_color=self.text_dark, hover_color="#5A9", font=self.font, width=100)
        analyze_button.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        # Create the settings button and place it on the grid
        settings_button = ctk.CTkButton(self, text="Settings", command=self.show_settings_window,
                                        fg_color=self.button_color,
                                        text_color=self.text_dark, hover_color="#5A9", font=self.font, width=70)
        settings_button.grid(row=0, column=0, padx=10, pady=10, sticky="nw")
        # Create the help button and place it on the grid
        help_button = ctk.CTkButton(self, text="Help", command=show_help, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=70)
        help_button.grid(row=0, column=0, padx=10, pady=40, sticky="nw")
        # Dictionary to track expanded frames
        self.expanded_frames = {}  # Dictionary to track expanded frames

    def load_and_apply_settings(self):
        """
            Load settings from the configuration and apply them.
            """
        settings = load_settings()
        self.renderer_var.set(settings.get("renderer", "quick"))
        self.verbose_var.set(settings.get("verbose", False))
        theme = settings.get("theme", "dark")
        change_theme(self, theme)

    def setup_ui(self):
        """
            Set up the initial UI elements and variables.
            """
        self.file_path_var = StringVar(value="No file selected")
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")

    def apply_theme(self):
        """
            Apply the theme settings to the application.
            """
        apply_theme(self)

    def save_all_settings(self, renderer, verbose, theme):
        """
            Save all settings including renderer, verbose, and theme.

            :param renderer: The renderer setting.
            :param verbose: The verbose setting.
            :param theme: The theme setting.
            """
        save_settings(renderer, verbose)
        change_theme(self, theme)

    def destroy(self):
        """
            Override the destroy method to set a flag before destroying the window.
            """
        self.main_window_destroyed = True
        super().destroy()

    def show_settings_window(self):
        """
            Show the settings window.
            """
        show_settings_window(self)

    def save_volatility_path(self, path):
        """
            Save the Volatility 3 path.

            :param path: The path to the Volatility 3 executable.
            """
        save_volatility_path(path)
        self.VOLATILITY_PATH = path
        messagebox.showinfo("Settings", "Volatility 3 path saved successfully.")

    def select_file(self):
        """
            Open a file dialog to select a memory dump file.
            """
        select_file(self)

    def create_plugin_dropdown(self, plugins, master):
        """
            Create the plugin dropdown menu.

            :param plugins: The list of plugins to include in the dropdown.
            :param master: The master widget for the dropdown.
            """
        create_plugin_dropdown(self, plugins, master)

    def update_plugin_dropdown(self, file_path):
        """
            Update the plugin dropdown menu based on the selected file.

            :param file_path: The path to the selected file.
            """
        update_plugin_dropdown(self, file_path)

    def get_volatility_plugins(self):
        """
            Get the list of available Volatility plugins.
            """
        return get_volatility_plugins(self)

    def categorize_plugins(self, plugins):
        """
            Categorize the given list of plugins.

            :param plugins: The list of plugins to categorize.
            :return: Categorized plugins.
            """
        return categorize_plugins(self, plugins)

    def run_analysis(self):
        """
            Run the analysis using the selected file, plugin, and settings.
            """
        # Retrieve values from the UI elements
        file_path = self.file_path_var.get()
        selected_plugin = self.plugin_dropdown_var.get()
        renderer = self.renderer_var.get()
        verbose = self.verbose_var.get()
        # Check if a valid plugin is selected
        if selected_plugin == "Select plugin" or selected_plugin == "Load file to select plugin":
            messagebox.showwarning("Invalid Selection", "Please select a valid plugin.")
            return
        # Check if a valid file path is provided
        if file_path and os.path.exists(file_path):
            self.show_progress_modal(file_path, selected_plugin, renderer, verbose)
        else:
            messagebox.showwarning("Invalid File", "Please select a valid file.")

    def show_progress_modal(self, file_path, plugin, renderer, verbose):
        """
            Display a progress modal while the analysis is running.

            :param file_path: The path to the file being analyzed.
            :param plugin: The selected plugin.
            :param renderer: The renderer option.
            :param verbose: The verbose mode setting.
            """
        self.cancel_flag = False
        # Create and configure the modal frame
        self.modal_frame = ctk.CTkFrame(self, fg_color="#333333", corner_radius=10)
        self.modal_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.3, relheight=0.25)
        # Add a header label to the modal
        header_label = ctk.CTkLabel(self.modal_frame, text="Analyzing...", font=("Arial", 18, "bold"),
                                    text_color="#FFFFFF")
        header_label.pack(pady=10)
        # Initialize and configure the progress bar and label
        progress_var = StringVar()
        progress_var.set("0%")
        progress_bar = ctk.CTkProgressBar(self.modal_frame, fg_color="#00BCD4", mode='determinate')
        progress_bar.pack(pady=10, padx=20, fill='x')
        progress_bar.set(0)
        progress_label = ctk.CTkLabel(self.modal_frame, textvariable=progress_var, font=("Arial", 14),
                                      text_color="#FFFFFF")
        progress_label.pack(pady=10)
        # Add a cancel button to the modal
        cancel_button = ctk.CTkButton(self.modal_frame, text="Cancel", command=self.cancel_analysis,
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font)
        cancel_button.pack(pady=10)
        # Initialize the queue and start processing it in a separate thread
        self.queue = queue.Queue()
        threading.Thread(target=self.process_queue).start()
        # Queue tasks for updating the progress bar and running the analysis
        self.queue.put(lambda: self.animate_progress_bar(progress_bar, progress_var))
        self.queue.put(
            lambda: self.execute_volatility(file_path, plugin, renderer, verbose, progress_bar, progress_var))

    def cancel_analysis(self):
        """
            Set the cancel flag to true to stop the analysis.
            """
        self.cancel_flag = True

    def process_queue(self):
        """
           Process tasks from the queue.
           """
        while True:
            task = self.queue.get()
            if task is None:
                break
            task()
            self.queue.task_done()

    def animate_progress_bar(self, progress_bar, progress_var):
        """
            Animate the progress bar to show the progress of the analysis.

            :param progress_bar: The progress bar widget.
            :param progress_var: The variable displaying the progress percentage.
            """
        for i in range(101):
            if self.cancel_flag:
                return
            progress_var.set(f"{i}%")
            progress_bar.set(i / 100)
            self.update_idletasks()

    def execute_volatility(self, file_path, plugin, renderer, verbose, progress_bar, progress_var):
        """
            Execute the Volatility tool with the specified parameters and update the progress bar.

            :param file_path: The path to the file being analyzed.
            :param plugin: The selected plugin.
            :param renderer: The renderer option.
            :param verbose: The verbose mode setting.
            :param progress_bar: The progress bar widget.
            :param progress_var: The variable displaying the progress percentage.
            """
        command = [sys.executable, self.VOLATILITY_PATH, "-r", renderer]
        if verbose:
            command.append("-v")
        command.extend(["-f", file_path, plugin])

        print("Executing command:", " ".join(command))

        try:
            # Start the subprocess to run the Volatility command
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            total_steps = 100
            for step in range(total_steps):
                if self.cancel_flag:
                    process.terminate()
                    self.create_result_tab(plugin, renderer, "Analysis canceled by user.")
                    return
                time.sleep(0.1)
                progress = (step + 1) / total_steps
                progress_var.set(f"{int(progress * 100)}%")
                progress_bar.set(progress)
                self.update_idletasks()
            # Get the output and error messages from the subprocess
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                content = stdout
                if verbose:
                    content = "Verbose mode enabled\n" + content
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
        """
            Remove the progress modal after the analysis is completed.
            """
        self.modal_frame.destroy()

    def create_result_tab(self, plugin, renderer, content):
        """
           Create a new tab to display the results of the analysis.

           :param plugin: The selected plugin.
           :param renderer: The renderer option.
           :param content: The content to display in the result tab.
           """
        tab_name = f"Result - {plugin} ({renderer})"
        if tab_name in self.tab_names:
            self.tabview.delete(tab_name)
            self.tab_names.remove(tab_name)

        tab_frame = self.tabview.add(tab_name)
        self.tab_names.add(tab_name)
        # Add a close button to the tab
        close_button = ctk.CTkButton(tab_frame, text="Close Tab", command=lambda: self.close_tab(tab_name),
                                     fg_color=self.button_color, text_color=self.text_dark,
                                     hover_color=self.header_color, font=self.font, width=80)
        close_button.pack(pady=10)

        self.display_treeview_content(tab_frame, content)

        self.tabview.set(tab_name)


    def save_results(self, content):
        """
            Save the analysis results to a file.

            :param content: The content to save.
            """
        file_path = filedialog.asksaveasfilename(
            title="Export",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("PDF files", "*.pdf"), ("Text files", "*.txt")],
            initialdir=os.getcwd()
        )
        if file_path:
            file_format = file_path.split('.')[-1]
            save_results_to_file(content, file_path, file_format)

    def display_treeview_content(self, tab_frame, content):
        """
           Display the analysis results in a treeview-like format.

           :param tab_frame: The frame in which to display the content.
           :param content: The content to display.
           """
        search_var = StringVar()
        # Create a frame for the search bar and buttons
        search_frame = ctk.CTkFrame(tab_frame, fg_color=self.background_color)
        search_frame.pack(pady=10)

        # Create and configure the search entry
        search_entry = ctk.CTkEntry(search_frame, textvariable=search_var, fg_color=self.input_field_color,
                                    text_color=self.text_bright, font=self.font, width=300, justify='center')
        search_entry.grid(row=0, column=0, padx=10, pady=10)
        search_entry.insert(0, "Enter Search")
        search_entry.bind("<FocusIn>", lambda event: self.clear_placeholder(event, search_entry))
        search_entry.bind("<FocusOut>", lambda event: self.add_placeholder(event, search_entry))
        search_entry.bind("<Return>", lambda event: search_text(text_widget, search_var, content))
        # Create and configure the search button
        search_button = ctk.CTkButton(search_frame, text="Search",
                                      command=lambda: search_text(text_widget, search_var, content),
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font, width=150)
        search_button.grid(row=0, column=1, padx=10, pady=10)
        # Create and configure the remove search button
        remove_search_button = ctk.CTkButton(search_frame, text="Remove Search",
                                             command=lambda: remove_search(text_widget, content, search_var),
                                             fg_color=self.button_color, text_color=self.text_dark,
                                             hover_color=self.header_color, font=self.font, width=150)
        remove_search_button.grid(row=0, column=2, padx=10, pady=3)
        # Create and configure the expand button
        expand_button = ctk.CTkButton(search_frame, text="Expand",
                                      command=lambda: self.expand_treeview(tree_frame, expand_button),
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font, width=150)
        expand_button.grid(row=0, column=3, padx=10, pady=10)
        # Add an export button to the tab
        save_button = ctk.CTkButton(search_frame, text="Export", command=lambda: self.save_results(content),
                                    fg_color="#E46F2E", text_color=self.text_dark,
                                    hover_color=self.header_color, font=self.font, width=100)
        save_button.grid(row=0, column=4, padx=10, pady=10)

        # Create a frame for the treeview content
        tree_frame = ctk.CTkFrame(tab_frame, fg_color=self.background_color)
        tree_frame.pack(padx=10, pady=10, fill='both', expand=True)
        tree_frame.configure(height=400)
        # Create and configure the text widget for displaying the content
        text_widget = Text(tree_frame, wrap="none", bg="#262626", fg="#F5F5F5", font=("Courier New", 10), padx=10,
                           pady=10)
        text_widget.pack(padx=10, pady=10, fill='both', expand=True)
        text_widget.insert("1.0", content)
        text_widget.configure(state=tk.DISABLED)  # Make text read-only


        tree_frame.pack_propagate(False)
        self.expanded_frames[tree_frame] = False  # Initialize the expanded state

        # Check for verbose mode indicator and add a label if it exists
        if content.startswith("Verbose mode enabled"):
            verbose_label = ctk.CTkLabel(tree_frame, text="Verbose Mode Activated", font=self.font,
                                         text_color="#FF0000")
            verbose_label.pack(pady=5)

    def clear_placeholder(self, event, entry):
        """
           Clear the placeholder text in the search entry when focused.

           :param event: The focus event.
           :param entry: The search entry widget.
           """
        if entry.get() == "Enter Search":
            entry.delete(0, tk.END)
            entry.configure(text_color=self.text_bright)

    def add_placeholder(self, event, entry):
        """
          Add placeholder text to the search entry when focus is lost.

          :param event: The focus event.
          :param entry: The search entry widget.
          """
        if not entry.get():
            entry.insert(0, "Enter Search")
            entry.configure(text_color="grey")

    def expand_treeview(self, tree_frame, button):
        """
           Expand or collapse the treeview frame.

           :param tree_frame: The frame containing the treeview.
           :param button: The button that triggered the expansion or collapse.
           """
        frame_id = id(tree_frame)
        if frame_id not in self.expanded_frames:
            self.expanded_frames[frame_id] = False

        if not self.expanded_frames[frame_id]:
            new_height = 800
            button.configure(text="Collapse")
        else:
            new_height = 310
            button.configure(text="Expand")

        tree_frame.configure(height=new_height)
        self.expanded_frames[frame_id] = not self.expanded_frames[frame_id]

    def close_tab(self, tab_name):
        """
            Close the specified tab and remove it from the list of tab names.

            :param tab_name: The name of the tab to close.
            """
        self.tabview.delete(tab_name)
        self.tab_names.remove(tab_name)
