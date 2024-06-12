# Import necessary modules
import os  # For operating system related functionalities
import json  # For handling JSON data
import customtkinter as ctk  # For creating custom Tkinter widgets
from tkinter import filedialog, messagebox  # For file dialogs and message boxes

# Configuration file path
CONFIG_FILE = "config.json"


def load_volatility_path():
    """
    Loads the Volatility 3 executable path from the configuration file.

    :return: The Volatility 3 executable path if available, otherwise None.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)  # Load the JSON configuration
            return config.get("VOLATILITY_PATH", None)  # Get the Volatility path if it exists
    return None


def save_volatility_path(path):
    """
    Saves the given Volatility 3 executable path to the configuration file.

    :param path: The path to the Volatility 3 executable.
    """
    config = load_config()  # Load the current configuration
    config["VOLATILITY_PATH"] = path  # Update the Volatility path
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)  # Save the updated configuration


def prompt_for_volatility_path():
    """
    Prompts the user to select the Volatility 3 executable path using a file dialog.

    :return: The selected path if available, otherwise None.
    """
    path = filedialog.askopenfilename(
        title="Select Volatility 3 Script",
        filetypes=[("Python files", "*.py"), ("All files", "*.*")]  # Filter for Python files
    )
    if path:
        save_volatility_path(path)  # Save the selected path
        return path
    return None


def get_volatility_path():
    """
    Retrieves the Volatility 3 executable path, prompting the user if necessary.

    :return: The Volatility 3 executable path.
    """
    path = load_volatility_path()  # Load the path from the configuration file
    if not path or not os.path.exists(path):
        messagebox.showinfo("Volatility Path Not Found", "Please select the Volatility 3 vol.py script.")  # Inform user
        path = prompt_for_volatility_path()  # Prompt user to select the path
        if not path:
            messagebox.showerror("Path Selection Error", "Volatility path not set. The application will exit.")  # Error
            exit()  # Exit the application
    return path


def load_config():
    """
    Loads the configuration from the configuration file.

    :return: The configuration dictionary.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as config_file:
            return json.load(config_file)  # Load and return the JSON configuration
    return {}


def save_settings(renderer, verbose):
    """
    Saves the application settings to the configuration file.

    :param renderer: The renderer setting ('quick' or 'pretty').
    :param verbose: The verbose mode setting (True or False).
    """
    config = load_config()  # Load the current configuration
    config["renderer"] = renderer  # Update the renderer setting
    config["verbose"] = verbose  # Update the verbose setting
    with open(CONFIG_FILE, "w") as config_file:
        json.dump(config, config_file)  # Save the updated configuration
    messagebox.showinfo("Settings", "Settings saved successfully.")  # Inform user


def load_settings():
    """
    Loads the application settings from the configuration file.

    :return: The configuration dictionary.
    """
    return load_config()


def change_theme(self, new_theme):
    """
    Changes the application theme and applies it.

    :param self: The application instance.
    :param new_theme: The selected theme ('light' or 'dark').
    """
    if new_theme.lower() == "light":
        self.background_color = "#F3EDE4"
        self.header_color = "#D8D2CB"
        self.button_color = "#62B4B7"
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

    apply_theme(self)  # Apply the new theme
    # Set the appearance mode based on the selected theme
    ctk.set_appearance_mode("light" if new_theme.lower() == "light" else "dark")


def apply_theme(self):
    """
    Applies the current theme to the application.

    :param self: The application instance.
    """
    self.configure(bg=self.background_color)  # Set the background color
    self.tabview.configure(fg_color=self.background_color)  # Set the tabview color

    for widget in self.winfo_children():
        if isinstance(widget, ctk.CTkLabel):
            widget.configure(text_color=self.text_bright, bg_color=self.background_color)  # Set label colors
        elif isinstance(widget, ctk.CTkButton):
            widget.configure(fg_color=self.button_color, text_color=self.text_dark,
                             hover_color=self.header_color)  # Set button colors
        elif isinstance(widget, ctk.CTkFrame):
            widget.configure(fg_color=self.background_color)  # Set frame color
        elif isinstance(widget, ctk.CTkOptionMenu):
            widget.configure(fg_color=self.input_field_color, text_color=self.text_bright,
                             button_color=self.button_color,
                             button_hover_color=self.header_color)  # Set option menu colors
        elif isinstance(widget, ctk.CTkCheckBox):
            widget.configure(fg_color=self.input_field_color, text_color=self.text_bright)  # Set checkbox colors


def show_settings_window(self):
    """
    Displays the settings window for the application.

    :param self: The application instance.
    """
    # Create the settings modal window
    self.settings_modal = ctk.CTkFrame(self, fg_color=self.background_color, corner_radius=10)
    self.settings_modal.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

    # Header label
    header_label = ctk.CTkLabel(self.settings_modal, text="Settings", font=("Arial", 18, "bold"),
                                text_color=self.text_bright)
    header_label.pack(pady=10)

    # Theme selection label and option menu
    theme_label = ctk.CTkLabel(self.settings_modal, text="Select Theme:", font=self.font, text_color=self.text_bright)
    theme_label.pack(pady=10)

    theme_option = ctk.CTkOptionMenu(self.settings_modal, values=["Dark", "Light"],
                                     command=lambda new_theme: change_theme(self, new_theme),
                                     fg_color=self.input_field_color, text_color=self.text_bright,
                                     button_color=self.button_color, button_hover_color=self.header_color)
    theme_option.pack(pady=10)

    # Volatility path label and entry
    volatility_path_label = ctk.CTkLabel(self.settings_modal, text="Volatility 3 Path:", font=self.font,
                                         text_color=self.text_bright)
    volatility_path_label.pack(pady=10)

    volatility_path_entry = ctk.CTkEntry(self.settings_modal, width=300, fg_color=self.input_field_color,
                                         text_color=self.text_bright)
    volatility_path_entry.insert(0, self.VOLATILITY_PATH)  # Pre-fill with current Volatility path
    volatility_path_entry.pack(pady=10)

    save_path_button = ctk.CTkButton(self.settings_modal, text="Save Path",
                                     command=lambda: save_volatility_path(volatility_path_entry.get()),
                                     fg_color=self.button_color, text_color=self.text_dark,
                                     hover_color=self.header_color)
    save_path_button.pack(pady=10)

    # Renderer selection label and option menu
    renderer_label = ctk.CTkLabel(self.settings_modal, text="Default Renderer:", font=self.font,
                                  text_color=self.text_bright)
    renderer_label.pack(pady=10)

    renderer_option = ctk.CTkOptionMenu(self.settings_modal, variable=self.renderer_var,
                                        values=["quick", "pretty"],
                                        fg_color=self.input_field_color, text_color=self.text_bright,
                                        button_color=self.button_color, button_hover_color=self.header_color)
    renderer_option.pack(pady=10)

    # Verbose mode label and checkbox
    verbose_label = ctk.CTkLabel(self.settings_modal, text="Verbose Mode:", font=self.font, text_color=self.text_bright)
    verbose_label.pack(pady=10)

    verbose_option = ctk.CTkCheckBox(self.settings_modal, text="Enable", variable=self.verbose_var, onvalue=True,
                                     offvalue=False, fg_color=self.input_field_color, text_color=self.text_bright)
    verbose_option.pack(pady=10)

    # Save settings button
    save_settings_button = ctk.CTkButton(self.settings_modal, text="Save Settings",
                                         command=lambda: self.save_all_settings(renderer_option.get(),
                                                                                self.verbose_var.get(),
                                                                                theme_option.get()),
                                         fg_color=self.button_color, text_color=self.text_dark,
                                         hover_color=self.header_color)
    save_settings_button.pack(pady=10)

    # Close button
    close_button = ctk.CTkButton(self.settings_modal, text="Close", command=self.settings_modal.destroy,
                                 fg_color=self.button_color, text_color=self.text_dark,
                                 hover_color=self.header_color, font=self.font)
    close_button.pack(pady=10)
