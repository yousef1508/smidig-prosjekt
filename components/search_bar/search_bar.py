import customtkinter as ctk
import sys
import os

# Add the parent directory to sys.path to ensure imports work correctly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def search():
    query = search_var.get()
    print(f'Search bar: {query}')
    show_results_page()

def show_results_page():
    from components.results_page import results_page
    results_page.result_page()

# Initialize the main window
root = ctk.CTk()
root.title("Search Bar")

# Grid layout configuration
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Search bar frame
frame = ctk.CTkFrame(root)
frame.grid(column=0, row=0, padx=10, pady=10, sticky="nsew")

# Label
label = ctk.CTkLabel(frame, text="Search:", text_color="black")
label.grid(column=0, row=0, padx=10, pady=10, sticky="w")

# Search Entry box
search_var = ctk.StringVar()
search_entry = ctk.CTkEntry(frame, width=200, textvariable=search_var, fg_color="white", text_color="black")
search_entry.grid(column=1, row=0, padx=10, pady=10, sticky="ew")
search_entry.focus()

# Search button
search_button = ctk.CTkButton(frame, text="Search", command=search, fg_color="gray", text_color="black")
search_button.grid(column=2, row=0, padx=10, pady=10, sticky="w")

root.mainloop()





