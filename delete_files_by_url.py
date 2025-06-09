
import os
import json
import logging
import boto3
from urllib.parse import urlparse
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ──────────── Environment Variables ────────────────────────────────────────────

# Metadata table name (BirdTagMetadata-DDB)
METADATA_TABLE_NAME = os.environ["METADATA_TABLE"]
# Inverted-index table name (BirdTagTagIndex)
TAG_INDEX_TABLE_NAME = os.environ["TAG_INDEX_TABLE"]
# GSI on metadata table for thumbnail lookup (partition key = "GSI2_PK")
GSI2_NAME = os.environ["GSI2_NAME"]
# S3 bucket where uploads and thumbnails live
MEDIA_BUCKET = os.environ["MEDIA_BUCKET"]

dynamodb        = boto3.resource("dynamodb")
metadata_table  = dynamodb.Table(METADATA_TABLE_NAME)
tag_index_table = dynamodb.Table(TAG_INDEX_TABLE_NAME)
s3_client       = boto3.client("s3")


def lambda_handler(event, context):
    """
    Lambda_DeleteFiles: Bulk‐delete S3 objects (uploads + thumbnails) and remove their DynamoDB entries.
    Expects JSON body:
      {
        "urls": [
          "https://<bucket>.s3.<region>.amazonaws.com/upload-files/bird1.jpg",
          "https://<bucket>.s3.<region>.amazonaws.com/thumbnails/bird1-thumb.png",
          "https://<bucket>.s3.<region>.amazonaws.com/upload-files/rarebird.mp4"
        ]
      }
    For each URL:
      1. Determine if URL belongs to "thumbnails/" or "upload-files/".
      2. If thumbnail: look up (PK, SK) via GSI2 on Metadata; derive upload_key from fileURL.
         If upload: scan Metadata for fileURL == url; derive thumb_key from thumbURL if present.
      3. (Optional) Verify ownership via Cognito sub (commented out).
      4. Delete S3 objects (upload_key and/or thumb_key).
      5. Delete metadata row (PK, SK).
      6. Delete all TagIndex entries where SK == file’s SK.
    Returns:
      200 + { "deleted": [ { "url": "...", "status": "OK"|"NotFound"|"InvalidURL"|"Forbidden" }, ... ] }
      400 if request body invalid.
    """

    # 1. Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "Request body is not valid JSON" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    urls = body.get("urls")
    if not isinstance(urls, list) or len(urls) == 0:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "`urls` must be a non‐empty array" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    deleted_results = []

    # 3. Process each URL
    for url in urls:
        status = "OK"
        try:
            # 3a. Parse URL to get S3 key
            parsed = urlparse(url)
            key = parsed.path.lstrip("/")  # e.g. "thumbnails/bird1-thumb.png" or "upload-files/bird1.jpg"

            is_thumb  = key.startswith("thumbnails/")
            is_upload = key.startswith("upload-files/")
            if not (is_thumb or is_upload):
                status = "InvalidURL"
                raise Exception("Skip further processing")

            # 3b. Lookup (PK, SK) via metadata table
            file_sk    = None
            user_pk    = None
            upload_key = None
            thumb_key  = None

            if is_thumb:
                # 3b-i. Thumbnail case: use GSI2 to find the metadata row
                #    GSI2_PK = "THUMB#<thumb_key>"
                gsi2_pk = f"THUMB#{key}"
                resp = metadata_table.query(
                    IndexName=GSI2_NAME,
                    KeyConditionExpression=Key("GSI2_PK").eq(gsi2_pk),
                    ProjectionExpression="PK, SK, fileURL"
                )
                items = resp.get("Items", [])
                if not items:
                    status = "NotFound"
                    raise Exception("Skip further processing")

                metadata_item = items[0]
                file_sk       = metadata_item["SK"]
                user_pk       = metadata_item["PK"]

                # Derive upload_key from stored fileURL
                file_url = metadata_item["fileURL"]
                parsed_main = urlparse(file_url)
                upload_key  = parsed_main.path.lstrip("/")  # e.g. "upload-files/bird1.jpg"

                # Thumbnail key is simply `key`
                thumb_key = key

            else:  # is_upload
                # 3b-ii. Upload case: scan metadata table for fileURL == url
                resp = metadata_table.scan(
                    FilterExpression=Attr("fileURL").eq(url),
                    ProjectionExpression="PK, SK, thumbURL"
                )
                items = resp.get("Items", [])
                if not items:
                    status = "NotFound"
                    raise Exception("Skip further processing")

                metadata_item = items[0]
                file_sk       = metadata_item["SK"]
                user_pk       = metadata_item["PK"]

                # Upload key is `key`
                upload_key = key

                # Derive thumb_key if thumbURL exists
                thumb_url = metadata_item.get("thumbURL")
                if thumb_url:
                    parsed_thumb = urlparse(thumb_url)
                    thumb_key = parsed_thumb.path.lstrip("/")  # e.g. "thumbnails/bird1-thumb.png"
                else:
                    thumb_key = None

            # 3c. (Optional) Authorization check: ensure user_pk == f"USER#{user_sub}"
            # expected_pk = f"USER#{user_sub}"
            # if user_pk != expected_pk:
            #     status = "Forbidden"
            #     raise Exception("Skip further processing")

            # 3d. Delete S3 objects
            if upload_key:
                try:
                    s3_client.delete_object(Bucket=MEDIA_BUCKET, Key=upload_key)
                except Exception as e:
                    logger.exception(f"Failed to delete upload object '{upload_key}': {e}")
                    # Continue to attempt thumbnail and DB cleanup

            if thumb_key:
                try:
                    s3_client.delete_object(Bucket=MEDIA_BUCKET, Key=thumb_key)
                except Exception as e:
                    logger.exception(f"Failed to delete thumbnail object '{thumb_key}': {e}")
                    # Continue to attempt DB cleanup

            # 3e. Delete the metadata row
            metadata_table.delete_item(Key={"PK": user_pk, "SK": file_sk})

            # 3f. Delete all TagIndex entries where SK == file_sk
            #    (scan TagIndex for SK == file_sk)
            scan_kwargs = {
                "FilterExpression": Attr("SK").eq(file_sk),
                "ProjectionExpression": "PK, SK"
            }
            paginator = tag_index_table.meta.client.get_paginator("scan")
            for page in paginator.paginate(TableName=TAG_INDEX_TABLE_NAME, **scan_kwargs):
                for item in page.get("Items", []):
                    tag_index_table.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})

        except Exception as exc:
            if not str(exc).startswith("Skip further processing"):
                logger.exception(f"Error deleting URL '{url}': {exc}")
            deleted_results.append({"url": url, "status": status})
            continue

        # If no exception, status remains "OK"
        deleted_results.append({"url": url, "status": status})

    # 4. Return summary
    return {
        "statusCode": 200,
        "body": json.dumps({ "deleted": deleted_results }),
        "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
    }