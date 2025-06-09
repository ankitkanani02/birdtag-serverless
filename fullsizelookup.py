
import os
import urllib.parse
import boto3
import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─── Environment variables ─────────────────────────────────────────────────────
TABLE_NAME = os.environ["TABLE_NAME"]    # e.g. "BirdTagMetadata-DDB"
GSI2_NAME  = os.environ["GSI2_NAME"]     # e.g. "GSI2"

# Initialize DynamoDB resource & table
dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    """
    Expects: GET /fullsize?thumbURL=<thumbnail_s3_url>
    Returns: { "fileURL": "<full_size_url>" } or error if not a valid thumbnail
    """

    # 1. Extract thumbURL from query string
    params    = event.get("queryStringParameters") or {}
    thumb_url = params.get("thumbURL")

    if not thumb_url:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "thumbURL query parameter is required" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    # 2. Derive the thumbnail's S3 key (e.g. "thumbnails/foo-thumb.jpg")
    try:
        parsed    = urllib.parse.urlparse(thumb_url)
        thumb_key = parsed.path.lstrip("/")   # e.g. "thumbnails/foo-thumb.jpg"
    except Exception:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "Invalid thumbnail URL" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    # 2a. If URL is not under "thumbnails/", reject immediately
    if not thumb_key.startswith("thumbnails/"):
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "No thumbnail exists for that file type" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    # 3. Build the GSI2_PK value: "THUMB#<thumb_key>"
    gsi2_pk = f"THUMB#{thumb_key}"
    logger.info(f"Looking up GSI2_PK = {gsi2_pk}")

    # 4. Query the GSI-ThumbLookup index
    try:
        resp = table.query(
            IndexName = GSI2_NAME,
            KeyConditionExpression = boto3.dynamodb.conditions.Key("GSI2_PK").eq(gsi2_pk),
            ProjectionExpression    = "fileURL"
        )
    except Exception as e:
        logger.error(f"DynamoDB query failed for GSI2_PK='{gsi2_pk}': {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({ "error": "DynamoDB query failed" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    items = resp.get("Items", [])
    if not items:
        return {
            "statusCode": 404,
            "body": json.dumps({ "error": "Full-size file not found" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    # 5. Return the full-size URL from the first matching item
    full_url = items[0].get("fileURL")
    if not full_url:
        return {
            "statusCode": 404,
            "body": json.dumps({ "error": "fileURL attribute missing" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    return {
        "statusCode": 200,
        "body": json.dumps({ "fileURL": full_url }),
        "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
    }
   