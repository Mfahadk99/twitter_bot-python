import random
import undetected_chromedriver as uc
from twscrape import AccountsPool, API
import logging
from pymongo import MongoClient
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TwitterAuth:
    def __init__(self, mongo_uri="mongodb://localhost:27017"):
        self.pool = AccountsPool()
        self.db = MongoClient(mongo_uri).twitter_monitor
        self.failed_accounts = set()
        self.proxies = self.load_proxies()

    def load_proxies(self, proxy_file="proxies.txt"):
        try:
            with open(proxy_file) as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    async def add_account(self, username: str, password: str, email: str | None, email_password: str | None, mfa_code : str = None):
        try:
            # if proxy is None and self.proxies:
            #     proxy = random.choice(self.proxies)
            cookies = "auth_token=0c2950d4a3943995714c8cdc040124a6d00aa31f; ct0=b508b05c9d911e13b20cb4975e0f9f23e452381879cf877e958e69ad311044b410c80aa7bf475d19f4dfa6ce37597376f0a99b939bea9b80651d95f1857aeb1754fab4d0a14575e36843bf9ad7d437c1"
            await self.pool.add_account(username=username, password=password, email=email, email_password=email_password, mfa_code=mfa_code, cookies=cookies)

            account_data = {
                "username": username,
                "email": email,
                "password": password,
                "cookies": cookies,
                "added_at": datetime.utcnow(),
                "last_used": datetime.utcnow(),
                "email_password": email_password,
                "is_active": True,
                "auth_method": "selenium"
            }

            self.db.twitter_accounts.update_one(
                {"username": username},
                {"$set": account_data},
                upsert=True
            )

            logger.info(f"Successfully added account: {username} with cookies")
            return True

        except Exception as e:
            logger.error(f"Failed to add account {username}: {str(e)}")
            await self.disable_account(username)
            return False

    async def get_active_accounts(self):
        return list(self.db.twitter_accounts.find({"is_active": True}))

    async def disable_account(self, username: str):
        self.db.twitter_accounts.update_one(
            {"username": username},
            {"$set": {"is_active": False, "disabled_at": datetime.utcnow()}}
        )
        logger.warning(f"Disabled account: {username}")

    async def reactivate_all_accounts(self):
        result = self.db.twitter_accounts.update_many(
            {"is_active": False},
            {"$set": {"is_active": True, "reactivated_at": datetime.utcnow()}}
        )
        logger.info(f"Reactivated {result.modified_count} previously disabled accounts.")

    async def initialize_accounts(self):
        await self.reactivate_all_accounts()
        active_accounts = await self.get_active_accounts()
        for acc in active_accounts:
            try:
                username = acc["username"]
                password = acc["password"]
                email = acc.get("email")
                email_password = acc.get("email_password")
                cookies = "auth_token=0c2950d4a3943995714c8cdc040124a6d00aa31f; ct0=b508b05c9d911e13b20cb4975e0f9f23e452381879cf877e958e69ad311044b410c80aa7bf475d19f4dfa6ce37597376f0a99b939bea9b80651d95f1857aeb1754fab4d0a14575e36843bf9ad7d437c1"
                await self.pool.add_account(username, password, email, email_password, cookies=cookies)

                logger.info(f"Initialized account in pool: {username}")
            except Exception as e:
                logger.error(f"Failed to initialize account {acc.get('username')}: {str(e)}")

    async def add_accounts_from_file(self, filename="accounts.txt"):
        # with open("proxies.txt") as pf:
        #     proxies = [line.strip() for line in pf if line.strip()]
        with open(filename) as f:
            lines = [line.strip() for line in f if line.strip()]

        random.shuffle(lines)

        for i, line in enumerate(lines):
            parts = line.split(":")
            if len(parts) >= 5:
                username = parts[0]
                password = parts[1]
                email = parts[2]
                email_password = parts[3]
                mfa_code = parts[4]
                # proxy = proxies[i % len(proxies)] if proxies else None

                await self.add_account(
                    username=username,
                    password=password,
                    email=email,
                    email_password=email_password,
                    # proxy=proxy,
                    mfa_code=mfa_code
                )

    async def get_api(self, exclude_accounts=None, preferred_accounts=None):
        active_accounts = await self.get_active_accounts()

        if exclude_accounts:
            active_accounts = [acc for acc in active_accounts if acc["username"] not in exclude_accounts]

        if preferred_accounts:
            preferred = [acc for acc in active_accounts if acc["username"] in preferred_accounts]
            non_preferred = [acc for acc in active_accounts if acc["username"] not in preferred_accounts]
            active_accounts = preferred + non_preferred

        for account in active_accounts:
            username = account["username"]
            password = account.get("password")
            email = account.get("email")
            email_password = account.get("email_password")
            try:
                await self.add_account(username, password, email, email_password)
            except Exception as e:
                logger.error(f"Failed to add {username} to pool: {str(e)}")
        await self.pool.login_all()
        return API(self.pool)
