from ntscraper import Nitter

print("🧪 Test ntscraper...")
scraper = Nitter()

print("🔍 Recherche 'ransomware'...")
tweets = scraper.get_tweets('ransomware', mode='term', number=3)

print(f"📊 Résultat : {len(tweets.get('tweets', []))} tweets trouvés")
for tweet in tweets.get('tweets', [])[:3]:
    print(f"  - {tweet.get('text', '')[:80]}...")
