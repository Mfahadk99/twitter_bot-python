import hashlib
import os
import signal
import sys
import time

import streamlit as st
from pymongo import MongoClient
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone, timedelta
import asyncio
from twitter_auth import TwitterAuth
import subprocess
import extra_streamlit_components as stx


st.set_page_config(page_title="Twitter Monitor", layout="wide")

cookie_manager = stx.CookieManager()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@st.cache_resource
def get_db():
    return MongoClient("mongodb://localhost:27017").twitter_monitor


db = get_db()

if "user" not in st.session_state:
    st.session_state.user = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "Login"


def centered_container(content_fn):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        content_fn()


def show_auth_toggle():
    st.markdown("### 🔐 Authentication")
    centered_container(lambda: toggle_buttons())


def toggle_buttons():
    login_btn, signup_btn = st.columns(2)
    with login_btn:
        if st.button("🔑 Login", use_container_width=True):
            st.session_state.auth_mode = "Login"
    with signup_btn:
        if st.button("🆕 Sign Up", use_container_width=True):
            st.session_state.auth_mode = "Sign Up"


def signup():
    centered_container(lambda: signup_form())


def signup_form():
    st.subheader("📝 Create an Account")
    st.write("Fill in the form to sign up")
    st.divider()
    username = st.text_input("👤 Choose a username", key="signup_username")
    password = st.text_input("🔒 Choose a password", type="password", key="signup_password")
    confirm = st.text_input("🔒 Confirm password", type="password", key="signup_confirm")

    st.markdown("")
    if st.button("✅ Sign Up", use_container_width=True):
        if not username or not password or not confirm:
            st.error("All fields are required")
        elif password != confirm:
            st.error("Passwords do not match")
        elif db.users.find_one({"username": username}):
            st.error("Username already exists")
        else:
            db.users.insert_one({"username": username, "password": hash_password(password)})
            st.success("✅ Signup successful! Please log in.")
            st.session_state.auth_mode = "Login"


def login():
    centered_container(lambda: login_form())

def login_form():
    st.subheader("🔐 Login to Your Account")
    st.write("Enter your credentials to continue")
    st.divider()
    username = st.text_input("👤 Username", key="login_username")
    password = st.text_input("🔒 Password", type="password", key="login_password")

    st.markdown("")
    if st.button("🚀 Login", use_container_width=True):
        user = db.users.find_one({"username": username})
        if user and user["password"] == hash_password(password):
            st.session_state.user = username
            cookie_manager.set("auth_token", username, expires_at=datetime.now() + timedelta(days=1))
            st.success(f"👋 Welcome, {username}!")
            st.rerun()
        else:
            st.error("Invalid username or password")

def logout():
    with st.sidebar:
        st.write(f"👤 Logged in as: `{st.session_state.user}`")
        if st.button("🔓 Logout"):
            st.session_state.user = None
            cookie_manager.delete("auth_token")
            st.success("🚪 Logged out successfully")
            st.rerun()


if "user" not in st.session_state:
    auth_token = cookie_manager.get("auth_token")
    if auth_token:
        user = db.users.find_one({"username": auth_token})
        if user:
            st.session_state.user = auth_token
    else:
        st.session_state.user = None

if not st.session_state.user:
    show_auth_toggle()
    if st.session_state.auth_mode == "Login":
        login()
    else:
        signup()
    st.stop()
else:
    logout()


if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()

refresh_interval = 60
time_since_refresh = (datetime.now() - st.session_state.last_refresh).total_seconds()

if time_since_refresh > refresh_interval:
    st.session_state.last_refresh = datetime.now()
    st.rerun()
time.sleep(1)

st.title("Twitter Monitoring Dashboard")

pages = [
    "Solana Tokens",
    "Monitored Accounts",
    "Account Management",
    "Run Monitor"
]

selected_page = st.sidebar.radio("Navigation", pages)
if selected_page == "Solana Tokens":
    st.header("🪙 Solana Tokens Analysis")

    # Token Overview Metrics with Birdeye integration
    total_tokens = db.tokens.count_documents({})
    tokens_with_twitter = db.tokens.count_documents({"processed": True})
    rug_passed = db.tokens.count_documents({"rugCheck.passed": True})
    birdeye_tokens = db.tokens.count_documents({"source": "birdeye"})
    avg_score = list(db.tokens.aggregate([
        {"$match": {"rugCheck.score": {"$exists": True}}},
        {"$group": {"_id": None, "avgScore": {"$avg": "$rugCheck.score"}}}
    ]))
    avg_score = avg_score[0]['avgScore'] if avg_score else 0

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Tokens", total_tokens)
    col2.metric("Birdeye Tokens", birdeye_tokens)
    col3.metric("With Twitter Profiles", tokens_with_twitter)
    col4.metric("Passed Rug Check", rug_passed)
    col5.metric("Avg Rug Score", f"{avg_score:.2f}")

    # Market Cap Monitoring Section
    st.subheader("📈 Real-time Market Cap Monitoring")

    # Get tokens with recent market cap data
    recent_marketcap = list(db.tokens.find({
        "rugCheck.passed": True,
        "currentMarketCap": {"$exists": True}
    }).sort("lastMarketCapCheck", -1).limit(10))

    if recent_marketcap:
        for token in recent_marketcap:
            with st.container():
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.write(f"**{token.get('symbol', 'Unknown')}**")
                    st.caption(f"{token['tokenAddress'][:8]}...")
                with col2:
                    market_cap = token.get('currentMarketCap', 0)
                    st.metric("Market Cap", f"${market_cap:,.0f}" if market_cap else "N/A")
                with col3:
                    price = token.get('currentPrice', 0)
                    st.metric("Price", f"${price:.6f}" if price else "N/A")
                with col4:
                    last_check = token.get('lastMarketCapCheck')
                    if last_check:
                        st.caption(f"Updated: {last_check.strftime('%H:%M:%S')}")
                st.divider()
    else:
        st.info("No tokens with market cap data yet. Wait for monitoring to begin.")

    # Market Cap History Chart
    if st.button("📊 Show Market Cap Trends"):
        history_data = list(db.marketcap_history.find({}).sort("timestamp", -1).limit(100))
        if history_data:
            df_history = pd.DataFrame([{
                'timestamp': h['timestamp'],
                'token': h['tokenAddress'][:8] + '...',
                'marketCap': h['marketCap'],
                'price': h['price']
            } for h in history_data])

            fig = px.line(df_history, x='timestamp', y='marketCap', color='token',
                         title="Market Cap Over Time", 
                         labels={'marketCap': 'Market Cap ($)', 'timestamp': 'Time'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No market cap history available yet.")

    # Add filters (unchanged)
    st.subheader("🔍 Filter Tokens")
    col1, col2, col3 = st.columns(3)

    with col1:
        rug_status = st.selectbox("Rug Check Status", ["All", "Passed", "Failed"])

    with col2:
        min_score = st.number_input("Minimum Score", min_value=0, value=0, step=1)

    with col3:
        sort_by = st.selectbox("Sort By", ["Newest", "Highest Score", "Lowest Score"])

    # Build query based on filters (unchanged)
    query = {}
    if rug_status == "Passed":
        query["rugCheck.passed"] = True
    elif rug_status == "Failed":
        query["rugCheck.passed"] = False

    if min_score > 0:
        query["rugCheck.score"] = {"$gte": min_score}

    sort_criteria = [("createdAt", -1)]  # Default: newest first
    if sort_by == "Highest Score":
        sort_criteria = [("rugCheck.score", -1)]
    elif sort_by == "Lowest Score":
        sort_criteria = [("rugCheck.score", 1)]

    # Token List with Enhanced Details
    st.subheader("🔍 Token Details")
    tokens = list(db.tokens.find(query).sort(sort_criteria).limit(50))

    for token in tokens:
        token_address = token.get('tokenAddress', 'Unknown')
        rug_score = token.get('rugCheck', {}).get('score', 0)

        # Determine color based on score
        if rug_score >= 80:
            score_color = "#4CAF50"  # Green
        elif rug_score >= 50:
            score_color = "#FFC107"  # Yellow
        else:
            score_color = "#F44336"  # Red

        with st.expander(f"🪙 {token_address} | Score: {rug_score}"):
            # Create columns for layout
            col1, col2 = st.columns([1, 3])

            with col1:
                # Token address with copy button
                st.markdown(f"""
                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                    <span style="font-family: monospace; font-size: 0.9em; word-break: break-all;">
                        {token_address}
                    </span>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                <div style="border-left: 5px solid {score_color}; padding-left: 10px;">
                    <span style="float: right; font-weight: bold; color: {score_color}">
                        Score: {rug_score}
                    </span>
                </div>
                """, unsafe_allow_html=True)

                st.write(f"**Created:** {token.get('createdAt', datetime.utcnow()).strftime('%Y-%m-%d %H:%M')}")

                # Show token source
                source = token.get('source', 'dexscreener')
                source_emoji = "🦅" if source == "birdeye" else "📊"
                st.write(f"**Source:** {source_emoji} {source.title()}")

                # Show Birdeye-specific data if available
                if source == "birdeye":
                    current_mc = token.get('currentMarketCap')
                    current_price = token.get('currentPrice')
                    if current_mc:
                        st.write(f"**Current Market Cap:** ${current_mc:,.0f}")
                    if current_price:
                        st.write(f"**Current Price:** ${current_price:.6f}")

                    last_check = token.get('lastMarketCapCheck')
                    if last_check:
                        st.write(f"**Last Updated:** {last_check.strftime('%H:%M:%S')}")

                if 'rugCheck' in token:
                    rug = token['rugCheck']
                    status_color = "green" if rug.get('passed') else "red"
                    st.markdown(
                        f"**Rug Check:** <span style='color:{status_color}'>"
                        f"{'✅ Passed' if rug.get('passed') else '❌ Failed'}</span>",
                        unsafe_allow_html=True
                    )
                    st.write(f"**Score:** {rug_score}")
                    st.write(f"**Last Checked:** {rug.get('lastChecked', datetime.now()).strftime('%Y-%m-%d %H:%M')}")

                    if 'checks' in rug and isinstance(rug['checks'], list):
                        st.write("**Risk Analysis:**")
                        for check in rug['checks']:
                            level = check.get('level', '').capitalize()
                            level_color = {
                                'danger': 'red',
                                'warn': 'orange',
                                'good': 'green'
                            }.get(check.get('level', '').lower(), 'gray')
                            st.markdown(
                                f"- {check.get('name', 'Unknown')}: "
                                f"<span style='color:{level_color}'>{level}</span> - "
                                f"{check.get('description', '')}",
                                unsafe_allow_html=True
                            )

                # Twitter profile section (unchanged)
                twitter_profile = db.twitter_profiles.find_one({"tokenAddress": token_address})
                if twitter_profile:
                    st.write("**Twitter Profile**")
                    st.write(f"**Username:** @{twitter_profile.get('twitterUsername')}")

                    if 'verification' in twitter_profile:
                        verif = twitter_profile['verification']
                        st.write(f"🔹 Verified: {'✅' if verif.get('verified') else '❌'}")
                        st.write(f"🔹 Followers: {verif.get('followers', 0):,}")

                    if 'analysis' in twitter_profile:
                        analysis = twitter_profile['analysis']
                        if 'engagement_metrics' in analysis:
                            metrics = analysis['engagement_metrics']['aggregate']
                            st.write(f"🔹 Avg Likes: {metrics.get('average_likes', 0):.1f}")
                            st.write(f"🔹 Avg Retweets: {metrics.get('average_retweets', 0):.1f}")
                            st.write(f"🔹 Engagement Rate: {metrics.get('engagement_rate', 0) * 100:.1f}%")

                if 'tokenData' in token and 'links' in token['tokenData']:
                    st.write("**Links:**")
                    for link in token['tokenData']['links'][:3]:
                        st.write(f"- [{link.get('label', 'Link')}]({link.get('url')})")


elif selected_page == "Monitored Accounts":
    st.header("👥 Monitored Twitter Accounts")

    # Account Metrics with RugCheck integration - updated to exclude 0 follower accounts
    total_accounts = db.twitter_profiles.count_documents({"verification.followers": {"$gt": 0}})
    active_accounts = db.twitter_profiles.count_documents({
        "verification.status": "active",
        "verification.followers": {"$gt": 0}
    })
    verified_accounts = db.twitter_profiles.count_documents({
        "verification.verified": True,
        "verification.followers": {"$gt": 0}
    })
    high_score_accounts = db.twitter_profiles.count_documents({
        "rugCheck.score": {"$gte": 2},
        "verification.followers": {"$gt": 0}
    })

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Accounts", total_accounts)
    col2.metric("Active Accounts", active_accounts)
    col3.metric("Verified Accounts", verified_accounts)
    col4.metric("High Score", high_score_accounts)

    st.subheader("📊 Account Performance")
    accounts = list(db.twitter_profiles.find({
        "verification.followers": {"$gt": 0}
    }).sort("verification.followers", -1))

    for account in accounts:
        if account.get('verification', {}).get('followers', 0) <= 0:
            continue
        rug_score = account.get('rugCheck', {}).get('score', 0)
        if rug_score >= 2.5:
            border_color = "#4CAF50"  # Green
        elif rug_score >= 1.5:
            border_color = "#FFC107"  # Yellow
        else:
            border_color = "#F44336"  # Red

        with st.expander(f"🐦 @{account.get('twitterUsername', 'unknown')}", expanded=True):
            st.markdown(f"""
            <div style="border-left: 5px solid {border_color}; padding-left: 10px; margin-bottom: 10px;">
                <span style="float: right; font-weight: bold; color: {border_color}">
                    Score: {account.get('rugCheck', {}).get('score', 'N/A')}
                </span>
            </div>
            """, unsafe_allow_html=True)

            tab1, tab2, tab3, tab4 = st.tabs(["Profile", "Engagement", "Token Info", "Risk Analysis"])

            with tab1:  # Profile Tab
                col1, col2 = st.columns([1, 2])

                with col1:
                    if 'verification' in account:
                        verif = account['verification']
                        # Enhanced profile image handling
                        profile_img = verif.get('profileImage')
                        if profile_img:
                            st.image(profile_img, width=150,
                                     caption=f"@{account.get('twitterUsername', '')}")
                        else:
                            st.warning("No profile image available")

                        # Status indicator with color coding
                        status = verif.get('status', 'unknown').title()
                        status_color = {
                            'Active': 'green',
                            'Error': 'red',
                            'Not Found': 'orange'
                        }.get(status, 'gray')

                        st.markdown(f"""
                            **Name:** {verif.get('name', 'Unknown')}  
                            **Verified:** {'✅' if verif.get('verified') else '❌'}  
                            **Status:** <span style='color:{status_color}'>{status}</span>  
                            **Created:** {verif.get('created', datetime.now(timezone.utc)).strftime('%Y-%m-%d')}
                            """, unsafe_allow_html=True)

                with col2:
                    if 'verification' in account:
                        verif = account['verification']
                        st.markdown(f"**Bio:**\n\n{verif.get('bio', 'No bio available')}")
                        st.markdown("---")

                        # Enhanced metrics display
                        col2a, col2b, col2c = st.columns(3)
                        with col2a:
                            st.metric("Followers", f"{verif.get('followers', 0):,}")
                        with col2b:
                            st.metric("Following", f"{verif.get('following', 0):,}")
                        with col2c:
                            if 'analysis' in account:
                                engagement = account['analysis'].get('engagement_metrics', {}).get('aggregate', {})
                                st.metric("Engagement Rate",
                                          f"{engagement.get('engagement_rate', 0) * 100:.1f}%")

                        # Banner image with fallback
                        banner_img = verif.get('bannerImage')
                        if banner_img:
                            st.image(banner_img, use_container_width=True)
                        else:
                            st.info("No banner image available")

            with tab2:  # Engagement Tab
                if 'analysis' in account:
                    analysis = account['analysis']

                    # Enhanced aggregate metrics with sparklines
                    if 'engagement_metrics' in analysis and 'aggregate' in analysis['engagement_metrics']:
                        agg = analysis['engagement_metrics']['aggregate']

                        # Create a 2x2 grid for metrics
                        cols = st.columns(2)
                        with cols[0]:
                            st.markdown("**Activity Metrics**")
                            st.metric("Avg Likes", f"{agg.get('average_likes', 0):.1f}")
                            st.metric("Avg Retweets", f"{agg.get('average_retweets', 0):.1f}")

                        with cols[1]:
                            st.markdown("**Performance Metrics**")
                            st.metric("Engagement Rate", f"{agg.get('engagement_rate', 0) * 100:.1f}%")
                            st.metric("Tweets Analyzed", agg.get('tweets_analyzed', 0))

                    # Enhanced recent tweets display with sentiment analysis placeholder
                    if 'tweets' in analysis and analysis['tweets']:
                        st.subheader("Recent Tweets Performance")
                        for tweet in analysis['tweets'][:5]:
                            with st.container():
                                tweet_date = tweet.get('timestamp')
                                if isinstance(tweet_date, str):
                                    tweet_date = datetime.fromisoformat(tweet_date.replace('Z', '+00:00'))

                                # Create columns for metrics
                                m1, m2, m3, m4 = st.columns(4)
                                m1.metric("Likes", tweet['metrics'].get('likes', 0))
                                m2.metric("Retweets", tweet['metrics'].get('retweets', 0))
                                m3.metric("Replies", tweet['metrics'].get('replies', 0))
                                m4.metric("Views", tweet['metrics'].get('views', 0))

                                st.markdown(
                                    f"**{tweet_date.strftime('%Y-%m-%d %H:%M') if tweet_date else 'Unknown date'}**")
                                st.markdown(f"{tweet.get('content', '')}")

                                tweet_url = tweet.get('url')
                                if tweet_url:
                                    st.markdown(f"[View Tweet]({tweet_url})")
                                st.markdown("---")

            with tab3:  # Token Info Tab
                if 'tokenAddress' in account:
                    st.markdown(f"**Token Address:** `{account['tokenAddress']}`")

                # Enhanced token data display
                token_data = account.get('tokenData', {})
                if token_data:
                    cols = st.columns(2)
                    with cols[0]:
                        st.markdown(f"**Token Name:** {token_data.get('name', 'Unknown')}")
                        st.markdown(f"**Symbol:** {token_data.get('symbol', 'N/A')}")

                    with cols[1]:
                        if 'price' in token_data:
                            price_change = token_data.get('priceChange24h', 0)
                            st.metric(
                                "Price",
                                f"${token_data['price']:.4f}",
                                f"{price_change:.2f}%" if price_change else None,
                                delta_color="inverse"
                            )

                # Enhanced RugCheck summary
                if 'rugCheck' in account:
                    rug = account['rugCheck']
                    st.markdown("---")
                    st.markdown("**Rug Check Summary**")

                    cols = st.columns(3)
                    with cols[0]:
                        st.metric("Score", f"{rug.get('score', 0)}")
                    with cols[1]:
                        st.metric("Status", "✅ Passed" if rug.get('passed') else "❌ Failed")
                    with cols[2]:
                        st.metric("Last Checked", rug.get('lastChecked', datetime.now()).strftime('%Y-%m-%d'))

            with tab4:  # Risk Analysis Tab
                if 'rugCheck' in account and 'checks' in account['rugCheck']:
                    st.markdown("### Risk Assessment Breakdown")

                    # Categorize checks by level
                    risk_levels = {
                        'danger': [],
                        'warn': [],
                        'good': []
                    }

                    # Add type checking for checks
                    checks = account['rugCheck']['checks']
                    if isinstance(checks, list):
                        for check in checks:
                            if isinstance(check, dict):  # Only process dictionary items
                                level = check.get('level', 'good').lower()
                                risk_levels[level].append(check)
                            else:
                                logger.warning(f"Skipping non-dict check item: {check}")

                    # Display risks in order of severity
                    for level, checks in risk_levels.items():
                        if checks:
                            level_name = level.capitalize()
                            color = {
                                'danger': 'red',
                                'warn': 'orange',
                                'good': 'green'
                            }.get(level, 'gray')

                            st.markdown(f"#### <span style='color:{color}'>{level_name} Risks ({len(checks)})</span>",
                                        unsafe_allow_html=True)

                            for check in checks:
                                with st.container():
                                    st.markdown(f"**{check.get('name', 'Unknown')}**")
                                    st.markdown(f"*Description:* {check.get('description', 'No description')}")
                                    if 'details' in check:
                                        st.markdown("**Details:**")
                                        st.json(check['details'])
                                    st.markdown("---")

    # Add summary charts section
    st.markdown("---")
    st.subheader("📈 Account Performance Summary")

    col1, col2 = st.columns(2)

    with col1:
        # Rug Score distribution
        try:
            score_data = list(db.twitter_profiles.aggregate([
                {"$match": {"rugCheck.score": {"$exists": True}}},
                {"$bucket": {
                    "groupBy": "$rugCheck.score",
                    "boundaries": [0, 1, 2, 3],
                    "default": "Other",
                    "output": {"count": {"$sum": 1}}
                }}
            ]))

            if score_data:
                df_scores = pd.DataFrame(score_data)
                fig = px.pie(df_scores, names='_id', values='count',
                             title="RugCheck Score Distribution",
                             color='_id',
                             color_discrete_map={
                                 '0': '#F44336',
                                 '1': '#FFC107',
                                 '2': '#4CAF50',
                                 '3': '#2E7D32'
                             })
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Could not load score distribution: {str(e)}")

    with col2:
        # Followers vs Rug Score scatter plot
        try:
            account_data = list(db.twitter_profiles.find(
                {"verification.followers": {"$exists": True}, "rugCheck.score": {"$exists": True}},
                {"verification.followers": 1, "rugCheck.score": 1, "twitterUsername": 1}
            ).limit(100))

            if account_data:
                df_accounts = pd.DataFrame([{
                    "username": a.get("twitterUsername", ""),
                    "followers": a.get("verification", {}).get("followers", 0),
                    "score": a.get("rugCheck", {}).get("score", 0)
                } for a in account_data])

                fig = px.scatter(df_accounts, x="followers", y="score",
                                 hover_data=["username"],
                                 title="Followers vs RugCheck Score",
                                 labels={"followers": "Followers", "score": "RugCheck Score"})
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Could not load followers data: {str(e)}")

    # Engagement Trends Visualization
    st.subheader("📈 Engagement Trends")

    if accounts:
        # Prepare data for visualization
        engagement_data = []
        for account in accounts:
            if 'analysis' in account and 'engagement_metrics' in account['analysis']:
                metrics = account['analysis']['engagement_metrics']['aggregate']
                engagement_data.append({
                    'username': account['twitterUsername'],
                    'avg_likes': metrics.get('average_likes', 0),
                    'avg_retweets': metrics.get('average_retweets', 0),
                    'avg_replies': metrics.get('average_replies', 0),
                    'engagement_rate': metrics.get('engagement_rate', 0)
                })

        if engagement_data:
            df = pd.DataFrame(engagement_data)

            # Top performers
            st.markdown("### 🏆 Top Performers")
            cols = st.columns(3)
            with cols[0]:
                top_likes = df.nlargest(3, 'avg_likes')
                st.markdown("**Most Likes**")
                for _, row in top_likes.iterrows():
                    st.markdown(f"- @{row['username']} ({row['avg_likes']:.1f} avg)")

            with cols[1]:
                top_retweets = df.nlargest(3, 'avg_retweets')
                st.markdown("**Most Retweets**")
                for _, row in top_retweets.iterrows():
                    st.markdown(f"- @{row['username']} ({row['avg_retweets']:.1f} avg)")

            with cols[2]:
                top_engagement = df.nlargest(3, 'engagement_rate')
                st.markdown("**Highest Engagement**")
                for _, row in top_engagement.iterrows():
                    st.markdown(f"- @{row['username']} ({row['engagement_rate'] * 100:.1f}%)")

            # Engagement comparison chart
            fig = px.bar(df,
                         x='username',
                         y=['avg_likes', 'avg_retweets', 'avg_replies'],
                         title="Average Engagement by Account",
                         labels={'value': 'Count', 'variable': 'Metric'},
                         barmode='group')
            st.plotly_chart(fig, use_container_width=True)

elif selected_page == "Account Management":
    st.header("Twitter Account Management")

    with st.expander("Add New Twitter Account"):
        with st.form("new_account"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            email = st.text_input("Email")
            proxy = st.text_input("Proxy")
            email_password = password

            if st.form_submit_button("Add Account"):
                if username and password:
                    try:
                        auth = TwitterAuth()
                        auth.add_account(username, password, email, email_password, proxy)
                        db.twitter_accounts.insert_one({
                            "username": username,
                            "password": password,
                            "email": email,
                            "email_password": email_password,
                            "is_active": True,
                            "added_at": datetime.utcnow(),
                            "last_used": None,
                            "proxy": proxy
                        })
                        st.success("Account added successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error adding account: {str(e)}")
                else:
                    st.error("All fields including proxy file are required")

    with st.expander("Bulk Upload from File"):
        uploaded_file = st.file_uploader("Upload accounts file (username:password:email:email_password)", type=["txt"])
        if uploaded_file is not None:
            if st.button("Process Uploaded File"):
                try:
                    with open("accounts.txt", "wb") as f:
                        f.write(uploaded_file.getvalue())

                    auth = TwitterAuth()
                    asyncio.run(auth.add_accounts_from_file("accounts.txt"))
                    st.success("Accounts uploaded successfully!")
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")
                    st.error("All fields including proxy file are required")

    st.subheader("Active Twitter Accounts")
    accounts = list(db.twitter_accounts.find())

    if not accounts:
        st.info("No active accounts found")
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Active Accounts", len(accounts))

        for account in accounts:
            with st.expander(f"@{account['username']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**Added:** {account['added_at'].strftime('%Y-%m-%d %H:%M')}")
                    if 'last_used' in account and account['last_used']:
                        st.write(f"**Last used:** {account['last_used'].strftime('%Y-%m-%d %H:%M')}")
                    else:
                        st.write("**Last used:** Never")
                    if 'email' in account and account['email']:
                        st.write(f"**Email:** {account['email']}")
                    if 'proxy' in account and account['proxy']:
                        st.write(f`**Proxy:** {account['proxy']}")
                with col2:
                    btn_col1, btn_col2 = st.columns(2)
                    with btn_col1:
                        if st.button("Disable", key=f"disable_{account['username']}"):
                            auth = TwitterAuth()
                            asyncio.run(auth.disable_account(account['username']))
                            st.rerun()
                    with btn_col2:
                        if st.button("Delete", key=f"delete_{account['username']}"):
                            db.twitter_accounts.delete_one({"username": account['username']})
                            st.success(f"Account @{account['username']} deleted permanently!")
                            st.rerun()

if 'script_process' not in st.session_state:
    st.session_state.script_process = None

if selected_page == "Run Monitor":
    st.header("Script Execution")

    def run_monitor_script():
        if st.session_state.script_process is None:
            try:
                process = subprocess.Popen([sys.executable, os.path.join(os.getcwd(), "twitter_bot.py")])
                st.session_state.script_process = process
                st.success("Monitor started successfully!")
                # Update monitor status in database
                db.monitor_status.update_one(
                    {},  # Empty filter matches first document
                    {"$set": {"last_run": datetime.now(timezone.utc)}},
                    upsert=True
                )
            except Exception as e:
                st.error(f"Failed to start monitor: {str(e)}")
        else:
            st.warning("Monitor is already running.")

    def stop_monitor_script():
        process = st.session_state.script_process
        if process and process.poll() is None:
            try:
                os.kill(process.pid, signal.SIGTERM)
                st.session_state.script_process = None
                st.success("Monitor stopped successfully!")
            except Exception as e:
                st.error(f"Failed to stop monitor: {str(e)}")
        else:
            st.warning("No monitor process is running.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Monitoring", type="primary"):
            run_monitor_script()
    with col2:
        if st.button("Stop Monitoring", type="secondary"):
            stop_monitor_script()

    st.subheader("Monitoring Status")
    if st.session_state.script_process:
        st.success("✅ Monitoring is currently running")
        # Safely get last run time
        status = db.monitor_status.find_one() or {}
        last_run = status.get("last_run")
        if last_run:
            st.write(f"Last run: {last_run.strftime('%Y-%m-%d %H:%M')}")
        else:
            st.write("Last run: Never recorded")
    else:
        st.warning("⚠️ Monitoring is not currently running")

    st.subheader("Recent Activity Log")
    try:
        log_entries = list(db.monitor_logs.find().sort("timestamp", -1).limit(10))
        if log_entries:
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                message = entry.get('message', 'No message')
                if timestamp:
                    st.write(f"{timestamp.strftime('%Y-%m-%d %H:%M')} - {message}")
                else:
                    st.write(f"Unknown time - {message}")
        else:
            st.info("No recent log entries found")
    except Exception as e:
        st.error(f"Failed to load logs: {str(e)}")