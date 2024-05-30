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
    label= ctk.CTkLabel(frame, text=Search:), text_color=black)
    Label.grid(column=0, row=0, padx=10, pady=10, sticky=w)

#Search Entery box

    search_var =ctk.StringVar(
    search_entry = ctk.CTkEntry(frame, width=200, textervariable= search_var)
    search_entry.grid(column=1, row=0, padx=10, sticky= w)
    search_var = ctk.StringVar()
    search_entry = ctk.CTkEntry(frame, width=200, textvariable=search_var, fg_color="white", text_color="black")
    search_entry.grid(column=1, row=0, padx=10, pady=10, sticky="ew")
    search_entry.focus()

    search button
    search_button = ctk.CTkButton(frame, text="Search", command=search, fg_color="gray", text_color="black")
    search_button.grid(column=2, row=0, padx=10, pady=10, sticky="w")


    root.mainloop()
