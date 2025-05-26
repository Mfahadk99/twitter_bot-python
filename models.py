from pymongo import IndexModel
from pymongo.mongo_client import MongoClient


def setup_schema(db):

    db.twitter_accounts.create_indexes([
        IndexModel([("username", 1)], unique=True),
        IndexModel([("is_active", 1)])
    ])


    db.campaigns.create_indexes([
        IndexModel([("name", 1)], unique=True),
        IndexModel([("active", 1)]),
        IndexModel([("hashtag_pairs", 1)])
    ])


    db.posts.create_indexes([
        IndexModel([("url", 1)], unique=True),
        IndexModel([("campaign_id", 1)]),
        IndexModel([("username", 1)]),
        IndexModel([("hashtags", 1)]),
        IndexModel([("timestamp", -1)]),
        IndexModel([("processed", 1)])
    ])


    db.flagged_accounts.create_indexes([
        IndexModel([("username", 1), ("campaign_id", 1)], unique=True),
        IndexModel([("last_detected", -1)])
    ])


    db.hashtag_activity.create_indexes([
        IndexModel([("hashtag_pair", 1), ("date", 1)], unique=True),
        IndexModel([("is_surge", 1)])
    ])


if __name__ == "__main__":
    client = MongoClient("mongodb://localhost:27017")
    db = client.twitter_monitor
    setup_schema(db)
    print("Database schema initialized successfully")