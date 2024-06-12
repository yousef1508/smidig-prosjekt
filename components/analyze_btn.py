import customtkinter as ctk
from tkinter import filedialog, StringVar, messagebox, Text
import os
import queue
import time
import subprocess
import threading
import logging
import tkinter as tk
import sys
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

LOG_FILE = "app.log"

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def search_text(text_widget, search_var, content):
    search_term = search_var.get().lower()
    text_widget.configure(state=tk.NORMAL)  # Enable editing
    text_widget.delete("1.0", tk.END)  # Clear the text widget

    for line in content.splitlines():
        if search_term in line.lower():
            text_widget.insert(tk.END, line + "\n")
    text_widget.configure(state=tk.DISABLED)  # Disable editing


def remove_search(text_widget, content, search_var):
    search_var.set("")
    text_widget.configure(state=tk.NORMAL)  # Enable editing
    text_widget.delete("1.0", tk.END)  # Clear the text widget

    for line in content.splitlines():
        text_widget.insert(tk.END, line + "\n")
    text_widget.configure(state=tk.DISABLED)  # Disable editing


class VolatilityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.main_window_destroyed = False
        self.title("Volatility 3 Analysis Tool")

        # Load settings
        config = load_settings()
        self.renderer_var = StringVar(value=config.get("renderer", "quick"))
        self.verbose_var = ctk.BooleanVar(value=config.get("verbose", False))
        self.VOLATILITY_PATH = config.get("VOLATILITY_PATH", get_volatility_path())

        self.setup_ui()
        self.tab_names = set()
        self.background_color = "#262626"
        self.header_color = "#222222"
        self.button_color = "#A9DFD8"
        self.textbox_color = "#647A77"
        self.input_field_color = "#474747"
        self.text_bright = "#F5F5F5"
        self.text_dark = "#000000"
        self.font = ("Arial", 14)
        self.configure(bg=self.background_color)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6, 7, 8], weight=1)
        self.file_path_var = StringVar(value="No file selected")
        self.plugin_dropdown = None
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")

        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=8, column=0, columnspan=2, padx=20, pady=20, sticky="ew")
        header = ctk.CTkLabel(self, text="File Analysis", font=("Arial", 24, "bold"), text_color=self.text_bright,
                              bg_color=self.background_color)
        header.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="n")
        file_button = ctk.CTkButton(self, text="Select File", command=self.select_file, fg_color="#E46F2E",
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=100)
        file_button.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        file_label = ctk.CTkLabel(self, textvariable=self.file_path_var, font=self.font, text_color=self.text_bright,
                                  bg_color=self.background_color)
        file_label.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        self.dropdown_frame = ctk.CTkFrame(self, fg_color=self.background_color)
        self.dropdown_frame.grid(row=3, column=0, columnspan=2, padx=30, pady=10, sticky="n")

        renderer_dropdown = ctk.CTkOptionMenu(
            master=self.dropdown_frame, variable=self.renderer_var, values=["quick", "pretty"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font, width=200
        )
        renderer_dropdown.pack(side="top", pady=(0, 25), anchor="center")

        self.plugin_dropdown = ctk.CTkOptionMenu(
            master=self.dropdown_frame, variable=self.plugin_dropdown_var, values=["Load file to select plugin"],
            fg_color=self.input_field_color, text_color=self.text_bright, button_color=self.button_color,
            button_hover_color=self.header_color, font=self.font, width=200
        )
        self.plugin_dropdown.pack(side="top", pady=(0, 10), anchor="center")

        verbose_checkbox = ctk.CTkCheckBox(
            self, text="Verbose", variable=self.verbose_var, onvalue=True, offvalue=False,
            fg_color=self.input_field_color, text_color=self.text_bright, font=self.font
        )
        verbose_checkbox.grid(row=4, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        analyze_button = ctk.CTkButton(self, text="Analyze", command=self.run_analysis, fg_color="#E46F2E",
                                       text_color=self.text_dark, hover_color="#5A9", font=self.font, width=100)
        analyze_button.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky="n")
        settings_button = ctk.CTkButton(self, text="Settings", command=self.show_settings_window,
                                        fg_color=self.button_color,
                                        text_color=self.text_dark, hover_color="#5A9", font=self.font, width=70)
        settings_button.grid(row=0, column=0, padx=10, pady=10, sticky="nw")
        help_button = ctk.CTkButton(self, text="Help", command=show_help, fg_color=self.button_color,
                                    text_color=self.text_dark, hover_color="#5A9", font=self.font, width=70)
        help_button.grid(row=0, column=0, padx=10, pady=40, sticky="nw")

        self.expanded_frames = {}  # Dictionary to track expanded frames

    def load_and_apply_settings(self):
        settings = load_settings()
        self.renderer_var.set(settings.get("renderer", "quick"))
        self.verbose_var.set(settings.get("verbose", False))
        theme = settings.get("theme", "dark")
        change_theme(self, theme)

    def setup_ui(self):
        self.file_path_var = StringVar(value="No file selected")
        self.plugin_dropdown_var = StringVar(value="Load file to select plugin")

    def apply_theme(self):
        apply_theme(self)

    def save_all_settings(self, renderer, verbose, theme):
        save_settings(renderer, verbose)
        change_theme(self, theme)

    def destroy(self):
        self.main_window_destroyed = True
        super().destroy()

    def show_settings_window(self):
        show_settings_window(self)

    def save_volatility_path(self, path):
        save_volatility_path(path)
        self.VOLATILITY_PATH = path
        messagebox.showinfo("Settings", "Volatility 3 path saved successfully.")

    def select_file(self):
        select_file(self)

    def create_plugin_dropdown(self, plugins, master):
        create_plugin_dropdown(self, plugins, master)

    def update_plugin_dropdown(self, file_path):
        update_plugin_dropdown(self, file_path)

    def get_volatility_plugins(self):
        return get_volatility_plugins(self)

    def categorize_plugins(self, plugins):
        return categorize_plugins(self, plugins)

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
        self.cancel_flag = False
        self.modal_frame = ctk.CTkFrame(self, fg_color="#333333", corner_radius=10)
        self.modal_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.3, relheight=0.25)
        header_label = ctk.CTkLabel(self.modal_frame, text="Analyzing...", font=("Arial", 18, "bold"),
                                    text_color="#FFFFFF")
        header_label.pack(pady=10)
        progress_var = StringVar()
        progress_var.set("0%")
        progress_bar = ctk.CTkProgressBar(self.modal_frame, fg_color="#00BCD4", mode='determinate')
        progress_bar.pack(pady=10, padx=20, fill='x')
        progress_bar.set(0)
        progress_label = ctk.CTkLabel(self.modal_frame, textvariable=progress_var, font=("Arial", 14),
                                      text_color="#FFFFFF")
        progress_label.pack(pady=10)
        cancel_button = ctk.CTkButton(self.modal_frame, text="Cancel", command=self.cancel_analysis,
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font)
        cancel_button.pack(pady=10)

        self.queue = queue.Queue()
        threading.Thread(target=self.process_queue).start()

        self.queue.put(lambda: self.animate_progress_bar(progress_bar, progress_var))
        self.queue.put(
            lambda: self.execute_volatility(file_path, plugin, renderer, verbose, progress_bar, progress_var))

    def cancel_analysis(self):
        self.cancel_flag = True

    def process_queue(self):
        while True:
            task = self.queue.get()
            if task is None:
                break
            task()
            self.queue.task_done()

    def animate_progress_bar(self, progress_bar, progress_var):
        for i in range(101):
            if self.cancel_flag:
                return
            progress_var.set(f"{i}%")
            progress_bar.set(i / 100)
            self.update_idletasks()

    def execute_volatility(self, file_path, plugin, renderer, verbose, progress_bar, progress_var):
        command = [sys.executable, self.VOLATILITY_PATH, "-r", renderer]
        if verbose:
            command.append("-v")
        command.extend(["-f", file_path, plugin])

        print("Executing command:", " ".join(command))

        try:
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
        self.modal_frame.destroy()

    def create_result_tab(self, plugin, renderer, content):
        tab_name = f"Result - {plugin} ({renderer})"
        if tab_name in self.tab_names:
            self.tabview.delete(tab_name)
            self.tab_names.remove(tab_name)

        tab_frame = self.tabview.add(tab_name)
        self.tab_names.add(tab_name)

        close_button = ctk.CTkButton(tab_frame, text="Close Tab", command=lambda: self.close_tab(tab_name),
                                     fg_color=self.button_color, text_color=self.text_dark,
                                     hover_color=self.header_color, font=self.font, width=80)
        close_button.pack(pady=10)

        self.display_treeview_content(tab_frame, content)

        self.tabview.set(tab_name)


    def save_results(self, content):
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
        search_var = StringVar()

        search_frame = ctk.CTkFrame(tab_frame, fg_color=self.background_color)
        search_frame.pack(pady=10)

        search_entry = ctk.CTkEntry(search_frame, textvariable=search_var, fg_color=self.input_field_color,
                                    text_color=self.text_bright, font=self.font, width=300, justify='center')
        search_entry.grid(row=0, column=0, padx=10, pady=10)
        search_entry.insert(0, "Enter Search")
        search_entry.bind("<FocusIn>", lambda event: self.clear_placeholder(event, search_entry))
        search_entry.bind("<FocusOut>", lambda event: self.add_placeholder(event, search_entry))
        search_entry.bind("<Return>", lambda event: search_text(text_widget, search_var, content))

        search_button = ctk.CTkButton(search_frame, text="Search",
                                      command=lambda: search_text(text_widget, search_var, content),
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font, width=150)
        search_button.grid(row=0, column=1, padx=10, pady=10)

        remove_search_button = ctk.CTkButton(search_frame, text="Remove Search",
                                             command=lambda: remove_search(text_widget, content, search_var),
                                             fg_color=self.button_color, text_color=self.text_dark,
                                             hover_color=self.header_color, font=self.font, width=150)
        remove_search_button.grid(row=0, column=2, padx=10, pady=3)

        expand_button = ctk.CTkButton(search_frame, text="Expand",
                                      command=lambda: self.expand_treeview(tree_frame, expand_button),
                                      fg_color=self.button_color, text_color=self.text_dark,
                                      hover_color=self.header_color, font=self.font, width=150)
        expand_button.grid(row=0, column=3, padx=10, pady=10)

        save_button = ctk.CTkButton(search_frame, text="Export", command=lambda: self.save_results(content),
                                    fg_color="#E46F2E", text_color=self.text_dark,
                                    hover_color=self.header_color, font=self.font, width=100)
        save_button.grid(row=0, column=4, padx=10, pady=10)


        tree_frame = ctk.CTkFrame(tab_frame, fg_color=self.background_color)
        tree_frame.pack(padx=10, pady=10, fill='both', expand=True)
        tree_frame.configure(height=400)

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
        if entry.get() == "Enter Search":
            entry.delete(0, tk.END)
            entry.configure(text_color=self.text_bright)

    def add_placeholder(self, event, entry):
        if not entry.get():
            entry.insert(0, "Enter Search")
            entry.configure(text_color="grey")

    def expand_treeview(self, tree_frame, button):
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
        self.tabview.delete(tab_name)
        self.tab_names.remove(tab_name)
