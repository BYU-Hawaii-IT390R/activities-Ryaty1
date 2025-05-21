# setup_files.py
from pathlib import Path
import random, string

BASE = Path("test_root")

folders = [
    BASE / "docs",
    BASE / "logs",
    BASE / "docs/subfolder",
    BASE / "logs/archive"
]

for folder in folders:
    folder.mkdir(parents=True, exist_ok=True)

for i in range(5):
    for folder in folders:
        filename = folder / f"file{i}.txt"
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
        filename.write_text(content)

<<<<<<< HEAD
print(f"Test directories and files created under: {BASE.resolve()}") 
=======
print(f"Test directories and files created under: {BASE.resolve()}")
>>>>>>> de1fc3692490434201db47b72c9c0471c67eb335
