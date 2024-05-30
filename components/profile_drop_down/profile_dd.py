from tkinter import *
import customtkinter

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()

root.title("profiles")
root.geometry("700x450")




def create_profile_dd(root):
    def profile_picker(choice):
        my_label.configure(text=choice)

    profiles = ["windows", "mac", "linux"]
    my_option = customtkinter.CTkOptionMenu(root, values=profiles, command=profile_picker)

    my_option.pack(pady=10)

    my_label = customtkinter.CTkLabel(root, text="")
    my_label.pack(pady=10)


    return my_option

def main():

    create_profile_dd(root)
    root.mainloop()


if __name__ == "__main__":
    main()

