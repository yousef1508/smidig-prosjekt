# Import necessary modules from the ReportLab library
from reportlab.lib.pagesizes import letter, landscape  # For setting the page size and orientation of the PDF
from reportlab.lib import colors  # For setting colors in the PDF
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph  # For creating the PDF document, tables, and paragraphs
from reportlab.lib.styles import getSampleStyleSheet  # For getting predefined styles for the PDF
from reportlab.lib.units import inch  # For setting units in the PDF

# Import necessary modules from the Tkinter library
from tkinter import messagebox  # For displaying message boxes

# Import the csv module for handling CSV files
import csv


def save_results_to_file(output, file_path, file_format):
    """
    Saves the analysis results to a specified file.

    :param output: The analysis results to export.
    :param file_path: The path where the results should be saved.
    :param file_format: The format in which to save the results (csv, pdf, txt).
    """
    try:
        if not output:
            raise ValueError("Output is empty")  # Raise an error if the output is empty

        # Validate file path
        if not file_path:
            raise ValueError("File path is empty")  # Raise an error if the file path is empty
        if not isinstance(file_path, str):
            raise TypeError("File path must be a string")  # Raise an error if the file path is not a string

        # Validate file format
        if file_format not in ['csv', 'pdf', 'txt']:
            raise ValueError("Unsupported file format")  # Raise an error if the file format is not supported

        if file_format == 'csv':
            # Ensure the file path ends with '.csv'
            if not file_path.endswith('.csv'):
                file_path += '.csv'
            # Write the output to a CSV file
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                for line in output.splitlines():
                    writer.writerow(line.split('\t'))  # Split lines by tab and write to the CSV file
        elif file_format == 'pdf':
            # Ensure the file path ends with '.pdf'
            if not file_path.endswith('.pdf'):
                file_path += '.pdf'
            # Create a PDF with the output
            create_pdf(output, file_path)
        elif file_format == 'txt':
            # Ensure the file path ends with '.txt'
            if not file_path.endswith('.txt'):
                file_path += '.txt'
            # Write the output to a text file
            with open(file_path, 'w') as file:
                file.write(output)

        # Show a success message
        messagebox.showinfo("Success", f"Results successfully exported to {file_path}")
    except Exception as e:
        # Show an error message if an exception occurs
        messagebox.showerror("Error", f"Error exporting results: {e}")


def create_pdf(output, file_path):
    """
    Creates a PDF file with the analysis results.

    :param output: The analysis results to export.
    :param file_path: The path where the results should be saved.
    """
    # Create the PDF document with landscape orientation
    doc = SimpleDocTemplate(file_path, pagesize=landscape(letter))
    styles = getSampleStyleSheet()  # Get predefined styles for the PDF
    elements = []  # List to hold elements to be added to the PDF

    # Determine if the output is "quick" (tab-separated values) or "pretty" (formatted text)
    if '\t' in output:
        # Quick render (tab-separated values)
        data = [line.split('\t') for line in output.splitlines()]  # Split lines by tab
        headers = data[0]  # First row as headers
        body = data[1:]  # Remaining rows as body

        # Define column widths (adjust these values based on your data)
        col_widths = [1 * inch] * len(headers)

        # Create a table with the data
        table = Table([headers] + body, colWidths=col_widths)

        # Add style to the table
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Background color for headers
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Text color for headers
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center alignment for all cells
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Bold font for headers
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Padding for headers
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Background color for body
            ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid lines for all cells
        ]))

        # Add the table to the elements list
        elements.append(table)
    else:
        # Pretty render (formatted text)
        lines = output.splitlines()  # Split output by lines
        for line in lines:
            elements.append(Paragraph(line, styles['BodyText']))  # Add each line as a paragraph

    # Build the PDF with the elements
    doc.build(elements)
