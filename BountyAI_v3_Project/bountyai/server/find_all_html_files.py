import pathlib

root = pathlib.Path(__file__).parent.parent.parent

print("=== ALL HTML FILES IN PROJECT ===")
for p in root.glob("**/*.html"):
    print(f"File: {p} | Size: {p.stat().st_size} bytes")
