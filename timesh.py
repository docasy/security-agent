"""临时测试脚本 — push 前删掉"""
from src.storage.database import get_db
db = get_db()
records = db.list_recent(5)
print(f"=== SQLite {len(records)} records ===")
for r in records:
    print(f"  #{r['id']} [{r['task_type']}] {r['input_data'][:50]}... | {r['status']} | {r['created_at']}")
