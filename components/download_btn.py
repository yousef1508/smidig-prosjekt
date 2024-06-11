import csv
from tkinter import messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def save_results_to_file(output, file_path, file_format):
    """
    Saves the analysis results to a specified file.

    :param output: The analysis results to export.
    :param file_path: The path where the results should be saved.
    :param file_format: The format in which to save the results (csv, pdf).
    """
    try:
        if not output:
            raise ValueError("Output is empty")

        # Validate file path
        if not file_path:
            raise ValueError("File path is empty")

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string")

        # Validate file format
        if file_format not in ['csv', 'pdf']:
            raise ValueError("Unsupported file format")

        if file_format == 'csv':
            if not file_path.endswith('.csv'):
                file_path += '.csv'
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                for line in output.splitlines():
                    writer.writerow(line.split('\t'))
        elif file_format == 'pdf':
            if not file_path.endswith('.pdf'):
                file_path += '.pdf'
            create_pdf(output, file_path)

        messagebox.showinfo("Success", f"Results successfully exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error exporting results: {e}")

def create_pdf(content, file_path):
    """
    Creates a PDF file from the provided content using reportlab.

    :param content: The content to be written into the PDF.
    :param file_path: The path where the PDF should be saved.
    """
    c = canvas.Canvas(file_path, pagesize=letter)
    y = 750  # Initial y position
    for line in content.splitlines():
        c.drawString(100, y, line)
        y -= 15  # Move to the next line
        if y <= 50:  # Start a new page if y position goes beyond the bottom margin
            c.showPage()
            y = 750  # Reset y position for the new page
    c.save()
