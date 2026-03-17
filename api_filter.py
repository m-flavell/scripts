import os
import yaml
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


def extract_api_info(directory_path):
    api_summary = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as stream:
                    try:
                        content = yaml.safe_load(stream)
                        # Extract paths if they exist in the file
                        paths = content.get('paths', {})
                        if isinstance(paths, dict):
                            for path, methods in paths.items():
                                if isinstance(methods, dict):
                                    for method in methods.keys():
                                        if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                                            api_summary.append({
                                                'file': file,
                                                'url': path,
                                                'method': method.upper()
                                            })
                    except Exception as e:
                        print(f"Could not parse {file}: {e}")
    return api_summary


class ApiExtractorGui:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenAPI Endpoint Extractor")
        self.root.geometry("800x500")

        # Top Frame for folder selection
        self.top_frame = tk.Frame(root)
        self.top_frame.pack(pady=10)

        self.btn_select = tk.Button(self.top_frame, text="Select Root Folder", command=self.browse_folder)
        self.btn_select.pack(side=tk.LEFT, padx=5)

        self.lbl_path = tk.Label(self.top_frame, text="No folder selected", fg="grey")
        self.lbl_path.pack(side=tk.LEFT, padx=5)

        # Scrolled text area for results
        self.text_area = scrolledtext.ScrolledText(root, width=90, height=25)
        self.text_area.pack(padx=10, pady=10)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.lbl_path.config(text=folder_selected, fg="black")
            self.text_area.delete(1.0, tk.END)  # Clear previous results

            results = extract_api_info(folder_selected)

            if not results:
                self.text_area.insert(tk.END, "No valid OpenAPI paths found in this directory.")
                return

            # Format the output header
            header = f"{'FILE':<25} | {'METHOD':<8} | {'ENDPOINT'}\n"
            divider = "-" * 90 + "\n"
            self.text_area.insert(tk.END, header + divider)

            # Insert the findings
            for entry in results:
                line = f"{entry['file']:<25} | {entry['method']:<8} | {entry['url']}\n"
                self.text_area.insert(tk.END, line)


if __name__ == "__main__":
    root = tk.Tk()
    app = ApiExtractorGui(root)
    root.mainloop()
