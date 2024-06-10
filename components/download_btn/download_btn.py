import json
import csv
from tkinter import messagebox

def save_results_to_file(output, file_path, file_format):
    """
    Saves the analysis results to a specified file.

    :param output: The analysis results to export.
    :param file_path: The path where the results should be saved.
    :param file_format: The format in which to save the results (json, csv, pdf).
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
        if file_format not in ['json', 'csv', 'pdf']:
            raise ValueError("Unsupported file format")

        if file_format == 'json':
            if not file_path.endswith('.json'):
                file_path += '.json'
            with open(file_path, 'w') as file:
                json.dump(output, file, indent=4)
        elif file_format == 'csv':
            if not file_path.endswith('.csv'):
                file_path += '.csv'
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                for line in output.splitlines():
                    writer.writerow(line.split('\t'))
        elif file_format == 'pdf':
            if not file_path.endswith('.pdf'):
                file_path += '.pdf'
            with open(file_path, 'w') as file:
                for line in output.splitlines():
                    file.write(line + '\n')

        messagebox.showinfo("Success", f"Results successfully exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error exporting results: {e}")
