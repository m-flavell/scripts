import os
import yaml


def extract_api_info(directory_path):
    api_summary = []

    # Iterate through all files in the directory
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                file_path = os.path.join(root, file)

                with open(file_path, 'r') as stream:
                    try:
                        # Load YAML content
                        content = yaml.safe_load(stream)

                        # Check if 'paths' exists in this specific file
                        paths = content.get('paths', {})

                        # Handle files where 'paths' is a dictionary of endpoints
                        if isinstance(paths, dict):
                            for path, methods in paths.items():
                                # Standard OpenAPI structure has methods as keys under the path
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


# Usage
folder_path = 'C:/Users/mf896533/Documents/Pentests/2026/API/Intelligence'  # Replace with your folder path
results = extract_api_info(folder_path)

print(f"{'FILE':<25} | {'METHOD':<8} | {'ENDPOINT'}")
print("-" * 80)
for entry in results:
    print(f"{entry['file']:<25} | {entry['method']:<8} | {entry['url']}")