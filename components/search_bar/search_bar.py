import customtkinter as ctk
def search ():
    query = search_var.get()
    print(f'search bar: {query}')
    root =ctk.CTk()
    root.title(Search bar
#Grid layout
    root.columconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
# Search bar frame
    frame =ctk.CTkLabel(frame, text=search)
    frame.grid(column=0, row=0, padx=10, pady=10, sticky=nsew)

#Label
    label= ctk.CTkLabel(frame, text=Search:)
