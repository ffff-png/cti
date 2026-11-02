import asyncio
from twscrape import API

async def main():
    api = API("accounts.db")  # Base de données locale des comptes
    
    # Vos vraies valeurs (assurez-vous qu'elles sont exactes et complètes)
    auth_token = "52b05ffcd630734b95ea54411918ebe09d05b3c4"
    ct0 = "4c8182efcdd213381f96e38fd2baef8b33fd61b480a5ee6a42cf4174f1cc9a6f9c9315db87b03dabbf9266ae4a69ebfa8e9bbf6c702f851f51c01f223706da182fa2ee8cb069f3ff3394448ff7681228"
    
    # Construction correcte de la chaîne de cookies
    cookies = f"auth_token={auth_token}; ct0={ct0}"
    
    print("Ajout du compte au pool...")
    await api.pool.add_account_cookies("mon_compte_cti", cookies)
    print("✅ Compte ajouté avec succès !")

if __name__ == "__main__":
    asyncio.run(main())
