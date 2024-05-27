import tkinter as tk


root = tk.Tk()
root.title("Tkinter Example")

label = tk.Label(root, text="Hello world!")
label.pack()

root.mainloop()