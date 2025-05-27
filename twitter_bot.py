import json
import os
import asyncio
import time
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import List, Dict, Optional
import aiohttp
import base58
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
import logging
import pytz

from twitter_auth import TwitterAuth

try:
    from solders.solders import Keypair
except ImportError:
    from solders.keypair import Keypair

from twscrape import API, NoAccountError
from dotenv import load_dotenv
from twscrape.logger import set_log_level
from collections import deque

load_dotenv()
logging.getLogger().handlers = []

mst = pytz.timezone('MST')

dex_log_file_path = os.path.abspath("/static/dexscreener.txt")
os.makedirs(os.path.dirname(dex_log_file_path), exist_ok=True)

rug_log_file_path = os.path.abspath("/static/rugcheck.txt")
os.makedirs(os.path.dirname(rug_log_file_path), exist_ok=True)

dex_response_file_path = os.path.abspath("/static/dexscreener_response.txt")
os.makedirs(os.path.dirname(dex_response_file_path), exist_ok=True)

rug_response_file_path = os.path.abspath("/static/rugcheck_response.txt")
os.makedirs(os.path.dirname(rug_response_file_path), exist_ok=True)

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

dex_file_handler = RotatingFileHandler(
    dex_log_file_path,
    mode='a',
    maxBytes=5*1024*1024,
    backupCount=2,
    encoding='utf-8'
)
dex_file_handler.setFormatter(formatter)
dex_file_handler.setLevel(logging.INFO)

rug_file_handler = RotatingFileHandler(
    rug_log_file_path,
    mode='a',
    maxBytes=5*1024*1024,
    backupCount=2,
    encoding='utf-8'
)
rug_file_handler.setFormatter(formatter)
rug_file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

dex_logger = logging.getLogger('dexscreener')
dex_logger.setLevel(logging.INFO)
dex_logger.addHandler(dex_file_handler)

rug_logger = logging.getLogger('rugcheck')
rug_logger.setLevel(logging.INFO)
rug_logger.addHandler(rug_file_handler)

dex_logger.info("Dexscreener logging system initialized successfully")
dex_logger.info(f"Dexscreener log file location: {dex_log_file_path}")
dex_logger.info(f"File exists: {os.path.exists(dex_log_file_path)}")
dex_logger.info(f"File writable: {os.access(dex_log_file_path, os.W_OK)}")

rug_logger.info("Rugcheck logging system initialized successfully")
rug_logger.info(f"Rugcheck log file location: {rug_log_file_path}")
rug_logger.info(f"File exists: {os.path.exists(rug_log_file_path)}")
rug_logger.info(f"File writable: {os.access(rug_log_file_path, os.W_OK)}")

set_log_level("DEBUG")

class SolanaTwitterMonitor:
    def __init__(self, mongo_uri: str = "mongodb://localhost:27017"):
        self.mongo_uri = mongo_uri
        self.client = None
        self.db = None
        self.auth = TwitterAuth(mongo_uri)
        self.api = API(raise_when_no_account=True)
        self.poll_interval = 300
        self.monitor_interval = 900
        self.session = aiohttp.ClientSession()
        self.dexscreener_url = "https://api.dexscreener.com/token-profiles/latest/v1?chainId=solana"
        self.request_times = deque(maxlen=60)
        self.rate_limit = 60
        self.monitoring_task = None
        self.shutdown_flag = False
        self.rugcheck_auth_url = "https://api.rugcheck.xyz/auth/login/solana"
        self.rugcheck_api_url = "https://api.rugcheck.xyz/v1/tokens"
        self.wallet = self._initialize_wallet()
        self.rugcheck_token = None

        self.birdeye_url = "https://public-api.birdeye.so/defi/tokenlist"
        self.birdeye_headers = {
            "X-API-KEY": os.getenv("BIRDEYE_API_KEY"),
            'Accept': 'application/json',
            'x-chain': 'solana'
        }

    async def initialize_db(self):
        self.client = AsyncIOMotorClient(self.mongo_uri)
        self.db = self.client.twitter_monitor

    async def is_db_initialized(self) -> bool:
        return self.db is not None

    async def initialize_accounts(self):
        await self.auth.initialize_accounts()

    def _initialize_wallet(self):
        private_key = os.getenv("SOLANA_PRIVATE_KEY")
        if not private_key:
            raise ValueError("Please set the SOLANA_PRIVATE_KEY environment variable.")
        return Keypair.from_base58_string(private_key)

    def _sign_message(self, message: str) -> dict:
        message_bytes = message.encode("utf-8")
        signature = self.wallet.sign_message(message_bytes)
        signature_base58 = str(signature)
        signature_data = list(base58.b58decode(signature_base58))
        return {
            "data": signature_data,
            "type": "ed25519",
            "base58": signature_base58,
        }

    async def _login_to_rugcheck(self) -> str:
        message_data = {
            "message": "Sign-in to Rugcheck.xyz",
            "timestamp": int(time.time() * 1000),
            "publicKey": str(self.wallet.pubkey()),
        }
        message_json = json.dumps(message_data, separators=(',', ':'))
        signature = self._sign_message(message_json)

        payload = {
            "signature": {
                "data": signature["data"],
                "type": "ed25519",
            },
            "wallet": str(self.wallet.pubkey()),
            "message": message_data,
        }

        try:
            async with self.session.post(
                    self.rugcheck_auth_url,
                    headers={"Content-Type": "application/json"},
                    json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    with open(rug_response_file_path, 'a') as f:
                        f.write(json.dumps(data) + '\n')
                    return data["token"]
                rug_logger.error(f"Failed to login to Rugcheck: {response.status}")
                return None
        except Exception as e:
            rug_logger.error(f"Error logging in to Rugcheck: {str(e)}")
            return None

    async def _get_rugcheck_token(self) -> str:
        if not self.rugcheck_token:
            self.rugcheck_token = await self._login_to_rugcheck()
        return self.rugcheck_token

    async def _get_rugcheck_report(self, token_address: str) -> Optional[Dict]:
        token = await self._get_rugcheck_token()
        if not token:
            return None

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

        max_retries = 3
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                async with self.session.get(
                        f"{self.rugcheck_api_url}/{token_address}/report/summary",
                        headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        with open(rug_response_file_path, 'a') as f:
                            f.write(json.dumps(data) + '\n')
                        return data
                    elif response.status == 429:
                        retry_after = int(response.headers.get('Retry-After', 30))
                        rug_logger.warning(f"Rugcheck rate limited. Waiting {retry_after} seconds (attempt {attempt + 1}/{max_retries})")
                        await asyncio.sleep(retry_after)
                        continue
                    elif response.status == 400:
                        rug_logger.error(f"Invalid token address format for Rugcheck: {token_address}")
                        return None
                    else:
                        rug_logger.error(f"Rugcheck API error for {token_address}: HTTP {response.status}")
                        await asyncio.sleep(retry_delay)
                        continue
            except Exception as e:
                rug_logger.error(f"Error getting Rugcheck report for {token_address}: {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)

        return None

    async def handle_twitter_request(self, func, *args, max_retries=3, **kwargs):
        last_exception = None

        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                if hasattr(result, "__aiter__"):
                    items = [item async for item in result]
                    return items
                else:
                    awaited_result = await result
                    return awaited_result
            except NoAccountError:
                dex_logger.warning(f"No accounts available (attempt {attempt + 1}/{max_retries}), reinitializing...")
                last_exception = NoAccountError("No accounts available after reinitialization")
                await asyncio.sleep(5)
            except Exception as e:
                dex_logger.error(f"Twitter request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                last_exception = e
                await asyncio.sleep(5)

        rug_logger.error(f"Failed after {max_retries} attempts")
        raise last_exception if last_exception else Exception("Unknown error in handle_twitter_request")

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def rate_limited_get(self, url: str, headers: Optional[Dict] = None) -> Optional[Dict]:
        now = time.time()

        while self.request_times and now - self.request_times[0] > 60:
            self.request_times.popleft()

        if len(self.request_times) >= self.rate_limit:
            sleep_time = 60 - (now - self.request_times[0])
            rug_logger.warning(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds")
            await asyncio.sleep(sleep_time)

        try:
            async with self.session.get(url, headers=headers) as response:
                self.request_times.append(time.time())
                if response.status == 200:
                    data = await response.json()
                    return data
                else:
                    rug_logger.error(f"Failed to fetch data from {url}: HTTP {response.status}")
                    return None
        except Exception as e:
            rug_logger.error(f"Error in rate_limited_get for {url}: {str(e)}")
            return None

    async def fetch_birdeye_tokens(self) -> List[Dict]:
        try:
            rug_logger.info("Fetching tokens from Birdeye...")
            data = await self.rate_limited_get(self.birdeye_url, self.birdeye_headers)
            
            if not data:
                rug_logger.error("No data received from Birdeye")
                return []
            
            tokens = []
            if isinstance(data, dict):
                if 'data' in data and 'tokens' in data['data']:
                    tokens = data['data']['tokens']
                elif 'tokens' in data:
                    tokens = data['tokens']
                else:
                    tokens = [data] if isinstance(data, dict) else data
            elif isinstance(data, list):
                tokens = data
            
            rug_logger.info(f"Retrieved {len(tokens)} tokens from Birdeye")
            return tokens[:50]
            
        except Exception as e:
            rug_logger.error(f"Error fetching from Birdeye: {str(e)}")
            return []

    async def fetch_latest_solana_tokens(self) -> List[Dict]:
        try:
            birdeye_tokens = await self.fetch_birdeye_tokens()
            
            if not birdeye_tokens:
                rug_logger.warning("No tokens retrieved from Birdeye, using fallback")
                return []
            
            results = []
            
            for token in birdeye_tokens:
                token_address = None
                if isinstance(token, dict):
                    token_address = (token.get('address') or 
                                   token.get('tokenAddress') or 
                                   token.get('mint') or 
                                   token.get('id'))
                elif isinstance(token, str):
                    token_address = token
                
                if not token_address or len(token_address) != 44:
                    continue
                
                dex_logger.info(f"Processing token: {token_address}")
                
                metadata = await self.fetch_dexscreener_metadata(token_address)
                if metadata:
                    results.append(metadata)
                    dex_logger.info(f"Successfully processed token: {token_address}")
                
                await asyncio.sleep(0.5)
            
            rug_logger.info(f"Successfully processed {len(results)} tokens")
            return results
            
        except Exception as e:
            rug_logger.error(f"Error in fetch_latest_solana_tokens: {str(e)}")
            return []
       
    async def fetch_dexscreener_metadata(self, token_address: str) -> Optional[Dict]:
        try:
            url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
            data = await self.rate_limited_get(url)
            
            if not data:
                return None
            
            pairs = data.get('pairs', [])
            if not pairs:
                return None
            
            selected_pair = None
            for pair in pairs:
                info = pair.get('info', {})
                has_socials = 'socials' in info and info['socials']
                has_websites = 'websites' in info and info['websites']
                
                if has_socials or has_websites:
                    selected_pair = pair
                    break
            
            if not selected_pair:
                rug_logger.debug(f"No pair with social links found for token: {token_address}")
                return None
            
            base_token = selected_pair.get('baseToken', {})
            
            formatted_data = {
                "url": f"https://dexscreener.com/solana/{selected_pair.get('pairAddress', '').lower()}",
                "chainId": "solana",
                "tokenAddress": token_address,
                "icon": f"https://dd.dexscreener.com/ds-data/tokens/solana/{token_address}.png",
                "header": f"https://dd.dexscreener.com/ds-data/tokens/solana/{token_address}/header.png",
                "openGraph": f"https://cdn.dexscreener.com/token-images/og/solana/{token_address}?timestamp={int(time.time() * 1000)}",
                "description": selected_pair.get('info', {}).get('description', '') or base_token.get('name', ''),
                "links": []
            }
            
            info = selected_pair.get('info', {})
            if 'socials' in info:
                for social in info['socials']:
                    social_type = social.get('type', '').lower()
                    url = social.get('url', '')
                    if url:
                        formatted_data['links'].append({
                            "type": social_type,
                            "url": url
                        })
            
            if 'websites' in info:
                for website in info['websites']:
                    url = website.get('url', '')
                    if url:
                        formatted_data['links'].append({
                            "label": "Website",
                            "url": url
                        })
            if not formatted_data['links']:
                rug_logger.debug(f"No valid links found for token: {token_address}")
                return None
                
            return formatted_data
            
        except Exception as e:
            rug_logger.error(f"Error fetching DexScreener metadata for {token_address}: {str(e)}")
            return []

    async def is_token_processed(self, token_address: str) -> bool:
        if not await self.is_db_initialized():
            await self.initialize_db()
        result = await self.db.tokens.find_one({"tokenAddress": token_address})
        return result is not None

    async def basic_rug_check(self, token_data: Dict) -> Dict:
        token_address = token_data.get("tokenAddress")
        if not token_address:
            rug_logger.info(f"Token check failed: No token address provided")
            return {
                "passed": False,
                "checks": {},
                "score": 0,
                "lastChecked": datetime.now(mst),
                "error": "No token address provided"
            }

        rug_logger.info(f"Running rug check for token: {token_address}")
        report = await self._get_rugcheck_report(token_address)
        if not report:
            rug_logger.info(f"Rug check failed for token: {token_address} - No report")
            return {
                "passed": False,
                "checks": {},
                "score": 0,
                "lastChecked": datetime.now(mst),
                "error": "Failed to get Rugcheck report"
            }

        processed_risks = []
        if "risks" in report and report["risks"]:
            for risk in report["risks"]:
                if risk.get("level") == "warn":
                    risk["level"] = "good"
                processed_risks.append(risk)

        has_warnings = any(
            risk.get("level") in ["danger"]
            for risk in processed_risks
        )

        result = {
            "passed": not has_warnings,
            "checks": processed_risks,
            "score": report.get("score", 0),
            "score_normalised": report.get("score_normalised", 0),
            "lastChecked": datetime.now(mst),
            "report": report
        }

        if result["passed"]:
            rug_logger.info(f"Token passed rug check: {token_address}")
        else:
            rug_logger.info(f"Token failed rug check: {token_address}")

        return result

    def extract_username_from_url(self, url: str) -> Optional[str]:
        url = url.lower().strip()

        if "twitter.com/" in url or "x.com/" in url:
            domain = "twitter.com/" if "twitter.com/" in url else "x.com/"
            parts = url.split(domain)[1].split("/")
            if len(parts) >= 1:
                if parts[0] == "i" and len(parts) > 1 and parts[1] == "communities":
                    return None
                if len(parts) > 1 and parts[1] == "status":
                    return None
            if parts and parts[0] not in ["i", "home", "explore", "notifications", "messages"]:
                return parts[0].strip("@")

        return None

    async def extract_twitter_profiles(self, tokens: List[Dict]) -> List[Dict]:
        twitter_profiles = []
        processed_tokens = set()

        for token in tokens:
            print(f"token:{token}")
            if "links" not in token:
                print(f"come in not found token:{token}")
                continue

            token_address = token.get("tokenAddress", "")
            processed_tokens.add(token_address)
            print(f"processed_tokens:{processed_tokens}")

            if await self.is_token_processed(token_address):
                continue

            rug_check = await self.basic_rug_check(token)
            if not rug_check["passed"]:
                dex_logger.info(f"Skipping token {token_address} - failed basic rug check")
                continue

            for link in token["links"]:
                if link.get("type") == "twitter" or "twitter.com" in link.get("url", "") or "x.com" in link.get("url", ""):
                    profile_url = link["url"]
                    username = self.extract_username_from_url(profile_url)
                    if username:
                        twitter_profiles.append({
                            "tokenAddress": token_address,
                            "tokenData": token,
                            "twitterUsername": username,
                            "twitterUrl": profile_url,
                            "rugCheck": rug_check,
                            "processed": False,
                            "createdAt": datetime.now(mst)
                        })

        return twitter_profiles

    async def verify_twitter_account(self, username: str) -> Dict:
        try:
            user = await self.handle_twitter_request(self.api.user_by_login, username)
            if user:
                return {
                    "username": user.username,
                    "userId": user.id,
                    "name": user.displayname,
                    "verified": user.verified,
                    "bio": user.rawDescription,
                    "followers": user.followersCount,
                    "following": user.friendsCount,
                    "created": user.created,
                    "profileImage": user.profileImageUrl,
                    "bannerImage": user.profileBannerUrl,
                    "status": "active"
                }
        except Exception as e:
            dex_logger.error(f"Error verifying Twitter account @{username}: {str(e)}")
            return {"username": username, "status": "error", "error": str(e)}
        return {"username": username, "status": "not_found"}

    async def analyze_twitter_activity(self, username: str, user_id: str) -> Dict:
        analysis = {
            "tweets": [],
            "engagement_metrics": {
                "aggregate": {},
                "per_tweet": []
            },
            "last_updated": datetime.now(mst)
        }

        try:
            tweets = await self.handle_twitter_request(self.api.user_tweets, int(user_id), limit=20)

            if tweets and isinstance(tweets, list):
                processed_tweets = []
                per_tweet_metrics = []

                for tweet in tweets[:20]:
                    tweet_url = f"https://twitter.com/{username}/status/{tweet.id}"
                    tweet_data = {
                        "id": str(tweet.id),
                        "url": tweet_url,
                        "timestamp": tweet.date.isoformat(),
                        "content": tweet.rawContent,
                        "metrics": {
                            "likes": tweet.likeCount if hasattr(tweet, 'likeCount') else 0,
                            "retweets": tweet.retweetCount if hasattr(tweet, 'retweetCount') else 0,
                            "replies": tweet.replyCount if hasattr(tweet, 'replyCount') else 0,
                            "views": getattr(tweet, "viewCount", 0)
                        }
                    }
                    processed_tweets.append(tweet_data)
                    per_tweet_metrics.append(tweet_data["metrics"])

                analysis["tweets"] = processed_tweets

                total_likes = sum(t['metrics']['likes'] for t in processed_tweets)
                total_retweets = sum(t['metrics']['retweets'] for t in processed_tweets)
                total_replies = sum(t['metrics']['replies'] for t in processed_tweets)
                total_views = sum(t['metrics']['views'] for t in processed_tweets)
                tweet_count = len(processed_tweets)

                analysis["engagement_metrics"]["aggregate"] = {
                    "total_likes": total_likes,
                    "total_retweets": total_retweets,
                    "total_replies": total_replies,
                    "total_views": total_views,
                    "average_likes": total_likes / tweet_count if tweet_count > 0 else 0,
                    "average_retweets": total_retweets / tweet_count if tweet_count > 0 else 0,
                    "average_replies": total_replies / tweet_count if tweet_count > 0 else 0,
                    "average_views": total_views / tweet_count if tweet_count > 0 else 0,
                    "engagement_rate": (total_likes + total_retweets) / total_views if total_views > 0 else 0,
                    "tweets_analyzed": tweet_count
                }

                analysis["engagement_metrics"]["per_tweet"] = per_tweet_metrics

        except Exception as e:
            dex_logger.error(f"Error analyzing Twitter activity for @{username}: {str(e)}")
            analysis["error"] = str(e)
            analysis["status"] = "error"

        return analysis

    async def process_twitter_profiles(self, profiles: List[Dict]):
        if not await self.is_db_initialized():
            await self.initialize_db()

        for profile in profiles:
            try:
                username = profile["twitterUsername"]
                token_address = profile["tokenAddress"]
                rug_check = profile.get("rugCheck", {})

                await self.db.tokens.update_one(
                    {"tokenAddress": token_address},
                    {"$set": {
                        "rugCheck": {
                            "score": rug_check.get("score", 0),
                            "score_normalised": rug_check.get("score_normalised", 0),
                            "checks": rug_check.get("checks", []),
                            "lastChecked": rug_check.get("lastChecked", datetime.now(mst)),
                            "passed": rug_check.get("passed", False)
                        },
                        "processed": True,
                        "processedAt": datetime.now(mst)
                    }},
                    upsert=True
                )

                verification = await self.verify_twitter_account(username)
                profile["verification"] = verification

                if verification.get("status") == "active":
                    user_id = verification["userId"]
                    analysis = await self.analyze_twitter_activity(username, user_id)
                    profile["analysis"] = analysis

                await self.db.twitter_profiles.update_one(
                    {"tokenAddress": token_address, "twitterUsername": username},
                    {"$set": profile},
                    upsert=True
                )

                dex_logger.info(f"Processed Twitter profile @{username} for token {token_address}")

            except Exception as e:
                dex_logger.error(f"Error processing profile {profile.get('twitterUsername')}: {str(e)}")

    async def monitor_existing_accounts(self):
        dex_logger.info("Starting account monitoring background task")
        if not await self.is_db_initialized():
            await self.initialize_db()

        while not self.shutdown_flag:
            try:
                start_time = time.time()

                cursor = self.db.twitter_profiles.find({
                    "verification.status": "active",
                    "$or": [
                        {"lastMonitored": {"$exists": False}},
                        {"lastMonitored": {"$lt": datetime.now(mst) - timedelta(minutes=15)}}
                    ]
                }).limit(50)

                accounts = await cursor.to_list(length=50)

                if accounts:
                    dex_logger.info(f"Monitoring {len(accounts)} existing accounts")

                    updates = []
                    for account in accounts:
                        try:
                            user_id = account["verification"]["userId"]
                            username = account["twitterUsername"]

                            verification = await self.verify_twitter_account(username)
                            analysis = await self.analyze_twitter_activity(username, user_id)

                            updates.append(UpdateOne(
                                {"_id": account["_id"]},
                                {"$set": {
                                    "verification": verification,
                                    "analysis": analysis,
                                    "lastMonitored": datetime.now(mst)
                                }}
                            ))

                        except Exception as e:
                            dex_logger.error(f"Error monitoring account @{account.get('twitterUsername')}: {str(e)}")

                    if updates:
                        await self.db.twitter_profiles.bulk_write(updates)
                        dex_logger.info(f"Updated {len(updates)} accounts")

                elapsed = time.time() - start_time
                sleep_time = max(0, int(self.monitor_interval - elapsed))
                await asyncio.sleep(sleep_time)

            except Exception as e:
                dex_logger.error(f"Error in monitoring task: {str(e)}")
                await asyncio.sleep(60)

    async def run(self):
        dex_logger.info("Starting Solana Twitter monitoring system")
        await self.initialize_db()
        await self.initialize_accounts()

        self.monitoring_task = None
        self.shutdown_flag = False

        try:
            self.monitoring_task = asyncio.create_task(self.monitor_existing_accounts())

            while not self.shutdown_flag:
                try:
                    start_time = time.time()

                    tokens = await self.fetch_latest_solana_tokens()
                    if not tokens:
                        dex_logger.warning("No tokens received, waiting before retry...")
                        await asyncio.sleep(60)
                        continue

                    dex_logger.info(f"Fetched {len(tokens)} Solana tokens")
                    twitter_profiles = await self.extract_twitter_profiles(tokens)
                    dex_logger.info(f"Found {len(twitter_profiles)} Twitter profiles to analyze")

                    if twitter_profiles:
                        await self.process_twitter_profiles(twitter_profiles)

                    elapsed = time.time() - start_time
                    sleep_time = max(0, int(self.poll_interval - elapsed))
                    dex_logger.info(f"Sleeping for {sleep_time:.2f} seconds")
                    await asyncio.sleep(sleep_time)

                except asyncio.CancelledError:
                    dex_logger.info("Received shutdown signal")
                    break
                except Exception as e:
                    dex_logger.error(f"Error in main loop: {str(e)}", exc_info=True)
                    await asyncio.sleep(60)

        except Exception as e:
            dex_logger.critical(f"Critical error in main loop: {str(e)}", exc_info=True)
        finally:
            dex_logger.info("Shutting down...")
            self.shutdown_flag = True

            if self.monitoring_task and not self.monitoring_task.done():
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    dex_logger.info("Monitoring task cancelled successfully")
                except Exception as e:
                    dex_logger.error(f"Error while cancelling monitoring task: {str(e)}")

            await self.close()
            dex_logger.info("Shutdown complete")

    async def close(self):
        await self.session.close()
        if self.client:
            self.client.close()

async def main():
    monitor = SolanaTwitterMonitor()
    try:
        await monitor.run()
    except KeyboardInterrupt:
        dex_logger.info("Shutting down gracefully...")
    finally:
        await monitor.close()

if __name__ == "__main__":
    asyncio.run(main())