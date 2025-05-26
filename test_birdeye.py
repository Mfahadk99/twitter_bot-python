
import asyncio
import aiohttp
import os
from dotenv import load_dotenv

load_dotenv()

async def test_birdeye_api():
    """Test Birdeye API connectivity and endpoints"""
    
    birdeye_headers = {
        "X-API-KEY": os.getenv("BIRDEYE_API_KEY", ""),
        "Accept": "application/json"
    }
    
    base_url = "https://public-api.birdeye.so"
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Token list endpoint
        print("Testing Birdeye token list endpoint...")
        url = f"{base_url}/defi/tokenlist?sort_by=recently_update&sort_type=desc&offset=0&limit=5"
        
        try:
            async with session.get(url, headers=birdeye_headers) as response:
                print(f"Status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    print(f"Success! Found {len(data.get('data', {}).get('tokens', []))} tokens")
                    
                    # Test a specific token
                    if data.get('data', {}).get('tokens'):
                        token_address = data['data']['tokens'][0].get('address')
                        if token_address:
                            print(f"\nTesting token overview for: {token_address}")
                            token_url = f"{base_url}/defi/token_overview?address={token_address}"
                            
                            async with session.get(token_url, headers=birdeye_headers) as token_response:
                                print(f"Token overview status: {token_response.status}")
                                if token_response.status == 200:
                                    token_data = await token_response.json()
                                    if token_data.get('success'):
                                        token_info = token_data.get('data', {})
                                        print(f"Token: {token_info.get('symbol')} - MC: ${token_info.get('mc', 0):,.0f}")
                                    else:
                                        print("Token overview failed")
                                else:
                                    print(f"Token overview error: {token_response.status}")
                else:
                    error_text = await response.text()
                    print(f"Error: {error_text}")
                    
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_birdeye_api())
