import tkinter as tk
from tkinter import ttk

def analyze():
    # This function is executed when the "Analyze" button is clicked
    print("Analyzing...")

# Create the main window
root = tk.Tk()
root.title("File Analysis")
root.configure(bg='#2C2C2C')  # Background color

# Create a frame for layout
frame = tk.Frame(root, bg='#2C2C2C')
frame.pack(expand=True)  # Place the frame in the main window and make it expandable

# Style for Combobox and button
style = ttk.Style()
style.theme_use('clam')
style.configure("TCombobox", fieldbackground='#1C1C1C', background='#1C1C1C', foreground='white', font=('Arial', 12))
style.map("TCombobox", fieldbackground=[('readonly', '#1C1C1C')], selectbackground=[('readonly', '#1C1C1C')], selectforeground=[('readonly', 'white')])
style.configure("TButton", background='#A7E4D8', foreground='black', font=('Arial', 12, 'bold'))

# Add a Drop-down (Combobox) for Plugin
plugin_combobox = ttk.Combobox(frame, values=["Plugin 1", "Plugin 2", "Plugin 3", "Plugin 4", "Plugin 5", "Plugin 6", "Plugin 7", "Plugin 8", "Plugin 9", "Plugin 10", "Plugin 11", "Plugin 12", "Plugin 13"], style="TCombobox", state="readonly")
plugin_combobox.set("Choose Plug-in")
plugin_combobox.config(width=25)  # Adjust the width of the combobox
plugin_combobox.pack(pady=10)  # Place the combobox in the frame with padding

# Add the "Analyze" button
analyze_button = tk.Button(frame, text="ANALYZE", command=analyze, bg='#A7E4D8', fg='black', font=('Arial', 12, 'bold'))
analyze_button.config(width=20, height=2)  # Adjust the size of the button
analyze_button.pack(pady=20)  # Place the button in the frame with padding

# Start the main loop
root.mainloop()
