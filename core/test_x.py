from collectors.x import XCollector

c = XCollector()
c.configure({
    "accounts_db": "data/x_accounts.db",
    "keywords": ["ransomware"],
    "profiles": [],
    "max_posts": 5,
    "emit": "post",      # d'abord "post" pour voir les tweets bruts
})

for rec in c.collect():
    print(rec.content[:100], "|", rec.metadata["url"])

print(c.health())
