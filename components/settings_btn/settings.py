# components/settings_btn/settings.py

import os
import json
import customtkinter as ctk
from tkinter import filedialog, messagebox, StringVar, BooleanVar

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


def load_settings():
    if os.path.exists("settings.json"):
        with open("settings.json", "r") as settings_file:
            settings = json.load(settings_file)
            return settings
    return {}


def save_settings(renderer, verbose):
    settings = {
        "renderer": renderer,
        "verbose": verbose
    }
    with open("settings.json", "w") as settings_file:
        json.dump(settings, settings_file)
    messagebox.showinfo("Settings", "Settings saved successfully.")


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

    apply_theme(self)


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

    theme_option = ctk.CTkOptionMenu(self.settings_modal, values=["Dark", "Light"],
                                     command=lambda new_theme: change_theme(self, new_theme))
    theme_option.pack(pady=10)

    # Add settings for Volatility 3 path
    volatility_path_label = ctk.CTkLabel(self.settings_modal, text="Volatility 3 Path:", font=self.font,
                                         text_color="#FFFFFF")
    volatility_path_label.pack(pady=10)

    volatility_path_entry = ctk.CTkEntry(self.settings_modal, width=300)
    volatility_path_entry.insert(0, self.VOLATILITY_PATH)
    volatility_path_entry.pack(pady=10)

    save_path_button = ctk.CTkButton(self.settings_modal, text="Save Path",
                                     command=lambda: save_volatility_path(volatility_path_entry.get()))
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
                                         command=lambda: save_settings(renderer_option.get(),
                                                                       self.verbose_var.get()))
    save_settings_button.pack(pady=10)

    close_button = ctk.CTkButton(self.settings_modal, text="Close", command=self.settings_modal.destroy,
                                 fg_color=self.button_color, text_color=self.text_dark,
                                 hover_color=self.header_color, font=self.font)
    close_button.pack(pady=10)
