from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from tkinter import messagebox
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
            raise ValueError("Output is empty")

        # Validate file path
        if not file_path:
            raise ValueError("File path is empty")

        if not isinstance(file_path, str):
            raise TypeError("File path must be a string")

        # Validate file format
        if file_format not in ['csv', 'pdf', 'txt']:
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
        elif file_format == 'txt':
            if not file_path.endswith('.txt'):
                file_path += '.txt'
            with open(file_path, 'w') as file:
                file.write(output)

        messagebox.showinfo("Success", f"Results successfully exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error exporting results: {e}")

def create_pdf(output, file_path):
    """
    Creates a PDF file with the analysis results.

    :param output: The analysis results to export.
    :param file_path: The path where the results should be saved.
    """
    # Create the PDF document
    doc = SimpleDocTemplate(file_path, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Determine if the output is "quick" or "pretty"
    if '\t' in output:
        # Quick render (tab-separated values)
        data = [line.split('\t') for line in output.splitlines()]
        headers = data[0]
        body = data[1:]

        # Define column widths (adjust these values based on your data)
        col_widths = [1 * inch] * len(headers)

        # Create a table with the data
        table = Table([headers] + body, colWidths=col_widths)

        # Add style to the table
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        # Add the table to the elements
        elements.append(table)
    else:
        # Pretty render (formatted text)
        lines = output.splitlines()
        for line in lines:
            elements.append(Paragraph(line, styles['BodyText']))

    # Build the PDF
    doc.build(elements)
