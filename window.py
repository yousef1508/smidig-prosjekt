import tkinter as tk
from components.download_btn.download import create_save_button


def main():
    root = tk.Tk()
    root.title("Tkinter Example")

    bg_color = "#2e2e2e"
    root.configure(bg=bg_color)

    label = tk.Label(root, text="Hello, Tkinter!", fg="white", bg=bg_color, font=("Roboto", 16, "bold"))
    label.pack(pady=20)

    width_percentage = 0.7
    height_percentage = 0.7

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    window_width = int(screen_width * width_percentage)
    window_height = int(screen_height * height_percentage)

    x_position = (screen_width - window_width) // 2
    y_position = (screen_height - window_height) // 2

    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    # Create the save button using the download component
    create_save_button(root)

    root.mainloop()


if __name__ == "__main__":
    main()
