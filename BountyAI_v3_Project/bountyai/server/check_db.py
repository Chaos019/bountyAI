import sys
sys.path.insert(0, '.')
import server
n = server.sync_curated_programs()
print(f"Curated added: {n}")

import sqlite3
conn = sqlite3.connect('bountyai.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()
c.execute("SELECT category, COUNT(*) as cnt FROM programs WHERE is_active=1 GROUP BY category ORDER BY cnt DESC")
print("\nBy Category (after curated sync):")
for row in c.fetchall():
    print(f"  {row[0] or 'None'}: {row[1]}")
conn.close()
