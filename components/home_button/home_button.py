import tkinter as tk
from PIL import Image, ImageTk

def button_clicked():
    print("Button clicked!")

root = tk.Tk()

# Load the image
original_image = Image.open("home_icon.png")

# Calculate new dimensions
width, height = original_image.size
new_width = int(width * 0.15)
new_height = int(height * 0.15)

# Resize the image
resized_image = original_image.resize((new_width, new_height), Image.ANTIALIAS)

# Convert the resized image to Tkinter PhotoImage
tk_image = ImageTk.PhotoImage(resized_image)

# Creating a button with the resized image
button = tk.Button(root,
                   image=tk_image,
                   command=button_clicked,
                   bd=0,  # No border
                   bg="#a9dfd8",
                   cursor="hand2")

# Place the button at the top left corner of the screen
button.place(x=0, y=0)

root.mainloop()
