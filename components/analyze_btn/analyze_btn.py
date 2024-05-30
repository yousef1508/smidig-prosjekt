import customtkinter as ctk
from tkinter import filedialog, Toplevel, StringVar
import os
import subprocess
import threading
import time
from volatility3.framework import contexts, automagic, constants
from volatility3 import framework, plugins

# Set the full path to your vol.py script
VOLATILITY_PATH = r'C:\Users\youse\volatility3-develop\vol.py'


def main():
    root = ctk.CTk()
    root.title("Volatility 3 Analysis Tool")
    root.geometry("700x500")

    # Colors and font styling from design template
    background_color = "#262626"
    header_color = "#222222"
    button_color = "#A9DFD8"
    textbox_color = "#647A77"
    input_field_color = "#474747"
    text_bright = "#F5F5F5"
    text_dark = "#000000"
    font = ("Arial", 12)

    # Configure root window
    root.configure(bg=background_color)
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure([0, 1, 2, 3, 4, 5], weight=1)

    # Path variable to store the selected file path
    file_path_var = ctk.StringVar(value="No file selected")

    # Plugin dropdown variable
    plugin_dropdown_var = ctk.StringVar(value="Load file to select plugin")

    # Initial plugin dropdown as None
    plugin_dropdown = None

    def select_file():
        file_path = filedialog.askopenfilename(
            title="Select a Memory Dump File",
            filetypes=[("Memory dump files", "*.vmem;*.dmp;*.img;*.bin;*.mem"), ("All files", "*.*")],
            initialdir=os.getcwd()
        )
        if file_path:
            file_path_var.set(file_path)
            update_plugin_dropdown(file_path)

    def create_plugin_dropdown(root, plugins):
        global plugin_dropdown
        plugin_dropdown = ctk.CTkOptionMenu(
            root, variable=plugin_dropdown_var, values=plugins, fg_color=input_field_color, text_color=text_bright,
            button_color=button_color, button_hover_color=header_color, font=font
        )
        plugin_dropdown.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

    def update_plugin_dropdown(file_path):
        global plugin_dropdown
        if plugin_dropdown is not None:
            plugin_dropdown.destroy()
        plugins = get_volatility_plugins()
        categorized_plugins = categorize_plugins(plugins)
        create_plugin_dropdown(root, ["Select plugin"] + categorized_plugins)
        plugin_dropdown_var.set("Select plugin")

    def get_volatility_plugins():
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

    def categorize_plugins(plugins):
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

    def run_analysis():
        file_path = file_path_var.get()
        selected_plugin = plugin_dropdown_var.get()
        if selected_plugin == "Select plugin" or selected_plugin == "Load file to select plugin":
            output_text.delete("1.0", "end")
            output_text.insert("1.0", "Please select a valid plugin.")
            return
        if file_path and os.path.exists(file_path):
            show_progress_modal(root, file_path, selected_plugin)
        else:
            output_text.delete("1.0", "end")
            output_text.insert("1.0", "Please select a valid file.")

    def show_progress_modal(parent, file_path, plugin):
        modal = Toplevel(parent)
        modal.title("Analyzing...")
        modal.geometry("400x150")
        modal.configure(bg=background_color)
        modal.transient(parent)
        modal.grab_set()

        progress_var = StringVar()
        progress_var.set("0%")

        progress_bar = ctk.CTkProgressBar(modal, mode='indeterminate', fg_color=button_color)
        progress_bar.pack(pady=10, padx=20, fill='x')
        progress_bar.start()

        progress_label = ctk.CTkLabel(modal, textvariable=progress_var, font=font, text_color=text_bright,
                                      bg_color=background_color)
        progress_label.pack(pady=10)

        threading.Thread(target=execute_volatility, args=(file_path, plugin, modal, progress_bar, progress_var)).start()

    def execute_volatility(file_path, plugin, modal, progress_bar, progress_var):
        command = ["python", VOLATILITY_PATH, "-f", file_path, plugin]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                output_text.delete("1.0", "end")
                output_text.insert("1.0", stdout)
            else:
                output_text.delete("1.0", "end")
                output_text.insert("1.0", f"Error: {stderr}")
        except Exception as e:
            output_text.delete("1.0", "end")
            output_text.insert("1.0", str(e))
        finally:
            progress_bar.stop()
            progress_var.set("100%")
            modal.grab_release()
            modal.destroy()

    # UI Components
    file_button = ctk.CTkButton(root, text="Select File", command=select_file, fg_color=button_color,
                                text_color=text_dark, hover_color=header_color, font=font)
    file_button.grid(row=0, column=0, padx=20, pady=20, sticky="ew")

    file_label = ctk.CTkLabel(root, textvariable=file_path_var, font=font, text_color=text_bright,
                              bg_color=background_color)
    file_label.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

    analyze_button = ctk.CTkButton(root, text="Analyze", command=run_analysis, fg_color=button_color,
                                   text_color=text_dark, hover_color=header_color, font=font)
    analyze_button.grid(row=3, column=0, padx=20, pady=20, sticky="ew")

    output_text = ctk.CTkTextbox(root, width=400, height=200, font=font, text_color=text_bright, bg_color=textbox_color)
    output_text.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")

    # Make sure plugin dropdown is initially created with a placeholder
    create_plugin_dropdown(root, ["Load file to select plugin"])

    root.mainloop()


if __name__ == "__main__":
    main()
