from pathlib import Path
import argparse
import csv

def scan_txt_files(directory):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    txt_files = list(directory.rglob("*.txt"))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(txt_files)} text files:\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    total_size = 0
    file_data = []  # <-- Collect data for CSV here

    for file in txt_files:
        size_kb = file.stat().st_size / 1024
        total_size += size_kb
        rel_path = str(file.relative_to(directory))
        print(f"{rel_path:<40} {size_kb:>10.1f}")
        file_data.append([rel_path, f"{size_kb:.1f}"])  # <-- Add to file_data

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")

    # Write to output.csv in the current working directory
    with open("output.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["file", "size_kb"])
        writer.writerows(file_data)
    print("Results written to: output.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for .txt files.")
    parser.add_argument("path", help="Path to directory to scan")
    args = parser.parse_args()
    scan_txt_files(args.path)
