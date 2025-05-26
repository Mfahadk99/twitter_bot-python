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
        self.marketcap_monitor_interval = 15  # Monitor every 15 seconds for faster updates
        self.session = aiohttp.ClientSession()
        self.dexscreener_url = "https://api.dexscreener.com/token-profiles/latest/v1?chainId=solana"
        self.birdeye_base_url = "https://public-api.birdeye.so"
        self.birdeye_headers = {
            "X-API-KEY": os.getenv("BIRDEYE_API_KEY", ""),
            "Accept": "application/json"
        }
        self.request_times = deque(maxlen=60)
        self.rate_limit = 60
        self.monitoring_task = None
        self.shutdown_flag = False
        self.rugcheck_auth_url = "https://api.rugcheck.xyz/auth/login/solana"
        self.rugcheck_api_url = "https://api.rugcheck.xyz/v1/tokens"
        self.wallet = self._initialize_wallet()
        self.rugcheck_token = None
        self.birdeye_request_times = deque(maxlen=60)
        self.birdeye_rate_limit = 100  # Birdeye allows 100 requests per minute

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

    async def rate_limited_get(self, url: str) -> Optional[Dict]:
        now = time.time()

        while self.request_times and now - self.request_times[0] > 60:
            self.request_times.popleft()

        if len(self.request_times) >= self.rate_limit:
            sleep_time = 60 - (now - self.request_times[0])
            rug_logger.warning(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds")
            await asyncio.sleep(sleep_time)

        try:
            async with self.session.get(url) as response:
                self.request_times.append(time.time())
                if response.status == 200:
                    data = await response.json()
                    with open(dex_response_file_path, 'a') as f:
                        f.write(json.dumps(data) + '\n')
                    return data
                rug_logger.error(f"Failed to fetch data: HTTP {response.status}")
                return None
        except Exception as e:
            rug_logger.error(f"Error in rate_limited_get: {str(e)}")
            return None

    async def birdeye_rate_limited_get(self, url: str) -> Optional[Dict]:
        now = time.time()

        # Clean old requests from the time window
        while self.birdeye_request_times and now - self.birdeye_request_times[0] > 60:
            self.birdeye_request_times.popleft()

        # Check if we've hit the rate limit
        if len(self.birdeye_request_times) >= self.birdeye_rate_limit:
            sleep_time = 60 - (now - self.birdeye_request_times[0])
            dex_logger.warning(f"Birdeye rate limit reached. Sleeping for {sleep_time:.2f} seconds")
            await asyncio.sleep(sleep_time)

        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                async with self.session.get(url, headers=self.birdeye_headers, timeout=10) as response:
                    self.birdeye_request_times.append(time.time())
                    
                    if response.status == 200:
                        try:
                            data = await response.json()
                            return data
                        except Exception as json_error:
                            dex_logger.error(f"Failed to parse JSON from Birdeye: {json_error}")
                            return None
                    elif response.status == 429:
                        retry_after = int(response.headers.get('Retry-After', 60))
                        dex_logger.warning(f"Birdeye rate limited. Waiting {retry_after} seconds (attempt {attempt + 1}/{max_retries})")
                        await asyncio.sleep(retry_after)
                        continue
                    elif response.status == 400:
                        dex_logger.error(f"Bad request to Birdeye API: {url}")
                        return None
                    else:
                        dex_logger.error(f"Birdeye API error: HTTP {response.status} for URL: {url}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                        continue
                        
            except asyncio.TimeoutError:
                dex_logger.warning(f"Timeout requesting Birdeye API (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
            except Exception as e:
                dex_logger.error(f"Error in birdeye_rate_limited_get: {str(e)} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)

        return None

    async def fetch_birdeye_new_tokens(self) -> List[Dict]:
        """Fetch new tokens from Birdeye API"""
        try:
            # Get new tokens from Birdeye's new listings endpoint
            new_tokens_url = f"{self.birdeye_base_url}/defi/tokenlist?sort_by=recently_update&sort_type=desc&offset=0&limit=100"
            new_tokens_data = await self.birdeye_rate_limited_get(new_tokens_url)
            
            if not new_tokens_data or not new_tokens_data.get('success'):
                dex_logger.warning("Failed to fetch new tokens from Birdeye, trying trending tokens")
                # Fallback to trending tokens
                trending_url = f"{self.birdeye_base_url}/defi/trending"
                trending_data = await self.birdeye_rate_limited_get(trending_url)
                
                if not trending_data or not trending_data.get('success'):
                    dex_logger.error("Failed to fetch any tokens from Birdeye")
                    return []
                
                new_tokens_data = trending_data

            tokens = []
            token_list = new_tokens_data.get('data', {}).get('tokens', []) or new_tokens_data.get('data', [])
            
            # Process each token
            for token_info in token_list[:50]:  # Limit to first 50
                token_address = token_info.get('address')
                if not token_address or len(token_address) != 44:
                    continue
                
                # Skip if already processed recently
                if await self.is_token_processed(token_address):
                    continue
                
                # Get detailed token info
                detail_url = f"{self.birdeye_base_url}/defi/token_overview?address={token_address}"
                detail_data = await self.birdeye_rate_limited_get(detail_url)
                
                if detail_data and detail_data.get('success'):
                    token_detail = detail_data.get('data', {})
                    
                    # Filter tokens by basic criteria
                    market_cap = token_detail.get('mc', 0)
                    liquidity = token_detail.get('liquidity', 0)
                    
                    # Skip tokens with very low market cap or liquidity
                    if market_cap < 1000 or liquidity < 500:
                        continue
                    
                    # Convert Birdeye format to our expected format
                    processed_token = {
                        'tokenAddress': token_address,
                        'name': token_detail.get('name', ''),
                        'symbol': token_detail.get('symbol', ''),
                        'decimals': token_detail.get('decimals', 9),
                        'supply': token_detail.get('supply', 0),
                        'price': token_detail.get('price', 0),
                        'priceChange24h': token_detail.get('priceChange24h', 0),
                        'volume24h': token_detail.get('volume24h', 0),
                        'marketCap': market_cap,
                        'liquidity': liquidity,
                        'createdAt': datetime.now(mst),
                        'source': 'birdeye'
                    }
                    tokens.append(processed_token)
                    dex_logger.info(f"Processed Birdeye token: {token_address} - MC: ${market_cap:,.0f}")
                else:
                    dex_logger.warning(f"Failed to get details for token: {token_address}")
                
                # Small delay to avoid hitting rate limits
                await asyncio.sleep(0.2)
                
            dex_logger.info(f"Successfully fetched {len(tokens)} new tokens from Birdeye")
            return tokens
            
        except Exception as e:
            dex_logger.error(f"Error fetching tokens from Birdeye: {str(e)}")
            return []

    async def get_token_socials_from_dexscreener(self, token_address: str) -> Optional[Dict]:
        """Get social links for a token from DexScreener"""
        try:
            url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
            data = await self.rate_limited_get(url)
            
            if not data or 'pairs' not in data:
                return None
                
            # Look for the first pair with social links
            for pair in data['pairs']:
                if 'info' in pair and 'socials' in pair['info']:
                    return {
                        'links': [
                            {'type': social['type'], 'url': social['url']}
                            for social in pair['info']['socials']
                            if social.get('type') and social.get('url')
                        ]
                    }
            
            return None
            
        except Exception as e:
            dex_logger.error(f"Error getting socials from DexScreener for {token_address}: {str(e)}")
            return None

    async def monitor_token_marketcap(self, token_address: str) -> Optional[Dict]:
        """Monitor specific token's market cap and other metrics"""
        try:
            url = f"{self.birdeye_base_url}/defi/token_overview?address={token_address}"
            data = await self.birdeye_rate_limited_get(url)
            
            if data and data.get('success'):
                token_data = data.get('data', {})
                return {
                    'tokenAddress': token_address,
                    'price': token_data.get('price', 0),
                    'marketCap': token_data.get('mc', 0),
                    'volume24h': token_data.get('volume24h', 0),
                    'priceChange24h': token_data.get('priceChange24h', 0),
                    'liquidity': token_data.get('liquidity', 0),
                    'timestamp': datetime.now(mst)
                }
            
            return None
            
        except Exception as e:
            dex_logger.error(f"Error monitoring token {token_address}: {str(e)}")
            return None

    async def fetch_latest_solana_tokens(self) -> List[Dict]:
        try:
            # Step 1: Fetch new tokens from Birdeye
            dex_logger.info("Step 1: Fetching new tokens from Birdeye...")
            birdeye_tokens = await self.fetch_birdeye_new_tokens()
            
            if not birdeye_tokens:
                dex_logger.warning("No tokens from Birdeye!")
                return []

            # Step 2: Enhance tokens with DexScreener metadata (social links)
            dex_logger.info(f"Step 2: Enhancing {len(birdeye_tokens)} tokens with DexScreener metadata...")
            enhanced_tokens = []
            
            for token in birdeye_tokens:
                token_address = token.get("tokenAddress")
                if not token_address or len(token_address) != 44:
                    continue
                    
                # Skip if already processed recently
                if await self.is_token_processed(token_address):
                    dex_logger.debug(f"Skipping already processed token: {token_address}")
                    continue

                # Get social links from DexScreener
                socials_data = await self.get_token_socials_from_dexscreener(token_address)
                if socials_data and "links" in socials_data:
                    token["links"] = socials_data["links"]
                    enhanced_tokens.append(token)
                    dex_logger.info(f"Enhanced token with social links: {token_address}")
                else:
                    # Still include token even without social links for RugCheck
                    enhanced_tokens.append(token)
                    dex_logger.debug(f"No social links found for token: {token_address}")

                # Small delay to avoid hitting DexScreener rate limits
                await asyncio.sleep(0.3)

            dex_logger.info(f"Enhanced {len(enhanced_tokens)} tokens with metadata")
            return enhanced_tokens

        except Exception as e:
            dex_logger.error(f"Error in token fetching flow: {str(e)}")
            return []

    async def _fetch_dexscreener_tokens(self) -> List[Dict]:
        try:
            data = await self.rate_limited_get(self.dexscreener_url)
            if not data:
                return []

            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                if "results" in data:
                    return data["results"]
                return [data]
            rug_logger.error(f"Unexpected API response format: {type(data)}")
            return []
        except Exception as e:
            rug_logger.error(f"Error fetching from DexScreener API: {str(e)}")
            return []

    async def is_token_processed(self, token_address: str) -> bool:
        if not await self.is_db_initialized():
            await self.initialize_db()
        result = await self.db.tokens.find_one({"tokenAddress": token_address})
        return result is not None

    async def save_failed_token(self, token: Dict, rug_check: Dict):
        """Save tokens that failed RugCheck"""
        if not await self.is_db_initialized():
            await self.initialize_db()
        
        await self.db.tokens.update_one(
            {"tokenAddress": token["tokenAddress"]},
            {"$set": {
                **token,
                "rugCheck": rug_check,
                "processed": True,
                "processedAt": datetime.now(mst),
                "status": "failed_rugcheck"
            }},
            upsert=True
        )

    async def save_passed_token(self, token: Dict, rug_check: Dict):
        """Save tokens that passed RugCheck and mark for monitoring"""
        if not await self.is_db_initialized():
            await self.initialize_db()
        
        await self.db.tokens.update_one(
            {"tokenAddress": token["tokenAddress"]},
            {"$set": {
                **token,
                "rugCheck": rug_check,
                "processed": True,
                "processedAt": datetime.now(mst),
                "status": "passed_rugcheck",
                "monitorMarketCap": True  # Flag for market cap monitoring
            }},
            upsert=True
        )

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
        for risk in report.get("risks", []):
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
            token_address = token.get("tokenAddress", "")
            if not token_address or token_address in processed_tokens:
                continue

            processed_tokens.add(token_address)

            if await self.is_token_processed(token_address):
                continue

            # Step 3: Run RugCheck validation - CRITICAL STEP
            dex_logger.info(f"Step 3: Running RugCheck for token: {token_address}")
            rug_check = await self.basic_rug_check(token)
            
            if not rug_check["passed"]:
                dex_logger.info(f"❌ Token {token_address} FAILED RugCheck - excluding from dashboard")
                # Still save to DB but mark as failed
                await self.save_failed_token(token, rug_check)
                continue
            else:
                dex_logger.info(f"✅ Token {token_address} PASSED RugCheck - will be monitored")

            # Only process tokens that passed RugCheck
            # Look for Twitter links in the metadata we got from DexScreener
            if "links" not in token:
                dex_logger.info(f"No social links found for token: {token_address}")
                # Still save passed tokens even without Twitter
                await self.save_passed_token(token, rug_check)
                continue

            # Extract Twitter profiles for passed tokens
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

        dex_logger.info(f"Found {len(twitter_profiles)} Twitter profiles from tokens that passed RugCheck")
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

    async def monitor_token_marketcaps(self):
        """Background task to monitor market caps of tokens that passed rug check"""
        dex_logger.info("Starting market cap monitoring background task")
        if not await self.is_db_initialized():
            await self.initialize_db()

        while not self.shutdown_flag:
            try:
                start_time = time.time()

                # Find tokens that passed rug check and need market cap monitoring
                # Only monitor tokens that explicitly passed RugCheck
                cursor = self.db.tokens.find({
                    "status": "passed_rugcheck",  # Only tokens that passed our flow
                    "rugCheck.passed": True,
                    "source": "birdeye",
                    "monitorMarketCap": True,  # Explicitly flagged for monitoring
                    "$or": [
                        {"lastMarketCapCheck": {"$exists": False}},
                        {"lastMarketCapCheck": {"$lt": datetime.now(mst) - timedelta(seconds=self.marketcap_monitor_interval)}}
                    ]
                }).sort("processedAt", -1).limit(20)  # Focus on recently processed tokens

                tokens = await cursor.to_list(length=30)

                if tokens:
                    dex_logger.info(f"Monitoring market cap for {len(tokens)} tokens")

                    updates = []
                    successful_updates = 0
                    
                    for token in tokens:
                        try:
                            token_address = token["tokenAddress"]
                            market_data = await self.monitor_token_marketcap(token_address)

                            if market_data:
                                # Calculate market cap change
                                old_mc = token.get("currentMarketCap", 0)
                                new_mc = market_data["marketCap"]
                                mc_change = ((new_mc - old_mc) / old_mc * 100) if old_mc > 0 else 0

                                # Store market cap history
                                await self.db.marketcap_history.insert_one({
                                    "tokenAddress": token_address,
                                    "marketCap": new_mc,
                                    "price": market_data["price"],
                                    "volume24h": market_data["volume24h"],
                                    "priceChange24h": market_data["priceChange24h"],
                                    "liquidity": market_data["liquidity"],
                                    "marketCapChange": mc_change,
                                    "timestamp": market_data["timestamp"]
                                })

                                # Update token with latest data
                                updates.append(UpdateOne(
                                    {"tokenAddress": token_address},
                                    {"$set": {
                                        "currentMarketCap": new_mc,
                                        "currentPrice": market_data["price"],
                                        "currentVolume24h": market_data["volume24h"],
                                        "currentLiquidity": market_data["liquidity"],
                                        "marketCapChange": mc_change,
                                        "lastMarketCapCheck": datetime.now(mst)
                                    }}
                                ))

                                successful_updates += 1
                                dex_logger.info(f"Updated {token_address}: ${new_mc:,.0f} ({mc_change:+.1f}%)")

                            else:
                                # Mark as checked even if failed to avoid constant retries
                                updates.append(UpdateOne(
                                    {"tokenAddress": token_address},
                                    {"$set": {"lastMarketCapCheck": datetime.now(mst)}}
                                ))

                        except Exception as e:
                            dex_logger.error(f"Error monitoring market cap for {token.get('tokenAddress')}: {str(e)}")

                        # Small delay between requests
                        await asyncio.sleep(0.1)

                    if updates:
                        await self.db.tokens.bulk_write(updates)
                        dex_logger.info(f"Successfully updated {successful_updates}/{len(updates)} tokens")

                elapsed = time.time() - start_time
                sleep_time = max(5, int(self.marketcap_monitor_interval - elapsed))  # Minimum 5 second sleep
                await asyncio.sleep(sleep_time)

            except Exception as e:
                dex_logger.error(f"Error in market cap monitoring task: {str(e)}")
                await asyncio.sleep(30)  # Shorter retry delay

    async def run(self):
        dex_logger.info("Starting Solana Twitter monitoring system")
        await self.initialize_db()
        await self.initialize_accounts()

        self.monitoring_task = None
        self.shutdown_flag = False

        try:
            self.monitoring_task = asyncio.create_task(self.monitor_existing_accounts())
            self.marketcap_task = asyncio.create_task(self.monitor_token_marketcaps())

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

            if self.marketcap_task and not self.marketcap_task.done():
                self.marketcap_task.cancel()
                try:
                    await self.marketcap_task
                except asyncio.CancelledError:
                    dex_logger.info("Market cap monitoring task cancelled successfully")
                except Exception as e:
                    dex_logger.error(f"Error while cancelling market cap task: {str(e)}")

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