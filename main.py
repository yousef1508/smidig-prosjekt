from analyze_btn import VolatilityApp

if __name__ == "__main__":
    app = None
    try:
        app = VolatilityApp()

        # Get screen width and height
        screen_width = app.winfo_screenwidth()
        screen_height = app.winfo_screenheight()

        # Calculate window size (for example, 60% of screen size)
        window_width = int(screen_width * 0.5)
        window_height = int(screen_height * 0.5)

        # Calculate position to center the window
        position_right = int(screen_width / 2 - window_width / 2)
        position_down = int(screen_height / 2 - window_height / 2)

        # Set the geometry
        app.geometry(f"{window_width}x{window_height}+{position_right}+{position_down}")

        app.mainloop()
    except KeyboardInterrupt:
        print("Program terminated by user")
        if app:
            app.destroy()
