import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
from urllib.parse import urlparse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ──────────── Environment Variables ────────────────────────────────────────────
METADATA_TABLE_NAME   = os.environ["METADATA_TABLE_NAME"]   # e.g. "BirdTagMetadata-DDB"
TAG_INDEX_TABLE_NAME  = os.environ["TAG_INDEX_TABLE_NAME"]  # e.g. "BirdTagTagIndex"
GSI2_NAME             = os.environ["GSI2_NAME"]             # e.g. "GSI2"

# Initialize DynamoDB tables
dynamodb        = boto3.resource("dynamodb")
metadata_table  = dynamodb.Table(METADATA_TABLE_NAME)
tag_index_table = dynamodb.Table(TAG_INDEX_TABLE_NAME)


def lambda_handler(event, context):
    """
    Lambda_ManageTags: Bulk‐add or remove species tags on existing files.

    Expects:
      - event["requestContext"]["authorizer"]["claims"]["sub"] = cognito-sub (user's identity)
      - event["body"] = {
            "urls": [...],                     # List of full S3 URLs to either upload‐files/... or thumbnails/...
            "operation": 0 or 1,               # 0 = remove tags, 1 = add tags
            "tags": ["species,count", ...]     # e.g. ["Crow,2", "Pigeon,1"]
        }

    Returns:
      200 + { "updated": [ { "url": "...", "status": "OK"|"NotFound"|"TagNotFound"|"PermissionDenied" }, ... ] }
      400 / 401 / 500 on errors.
    """

    # 1. Parse & validate JSON body
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

    urls       = body.get("urls")
    operation  = body.get("operation")
    tags_list  = body.get("tags")

    # 1a. Validate top-level fields
    if not isinstance(urls, list) or len(urls) == 0:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "`urls` must be a non‐empty array" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }
    if operation not in (0, 1):
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "`operation` must be 0 (remove) or 1 (add)" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }
    if not isinstance(tags_list, list) or len(tags_list) == 0:
        return {
            "statusCode": 400,
            "body": json.dumps({ "error": "`tags` must be a non‐empty array of strings" }),
            "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
        }

    # 1b. Parse each "species,count" into (species:str, count:int)
    parsed_tags = {}
    for tag_str in tags_list:
        if not isinstance(tag_str, str) or "," not in tag_str:
            return {
                "statusCode": 400,
                "body": json.dumps({ "error": f"Invalid tag format: '{tag_str}'. Must be 'species,count'." }),
                "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
            }
        species, count_str = tag_str.split(",", 1)
        species = species.strip()
        count_str = count_str.strip()
        if not species:
            return {
                "statusCode": 400,
                "body": json.dumps({ "error": f"Species is empty in '{tag_str}'." }),
                "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
            }
        try:
            count_int = int(count_str)
            if count_int < 0:
                raise ValueError()
        except ValueError:
            return {
                "statusCode": 400,
                "body": json.dumps({ "error": f"Count must be a non‐negative integer in '{tag_str}'." }),
                "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
                
            }
        parsed_tags[species] = count_int



    updated_results = []

    # 2. Process each URL in turn
    for url in urls:
        result_status = "OK"
        try:
            # 2a. Determine if URL is a thumbnail vs. a main file.
            parsed = urlparse(url)
            path = parsed.path.lstrip("/")  
            # e.g. "thumbnails/crows_2-thumb.jpg"  or  "upload-files/crows_2.jpg"

            if path.startswith("thumbnails/"):
                url_type = "thumb"
                thumb_key = path                           # e.g. "thumbnails/abc123-thumb.jpg"

                # 2b. Find the metadata item via GSI2 on GSI2_PK = "THUMB#<thumb_key>"
                gsi2_pk = f"THUMB#{thumb_key}"
                resp   = metadata_table.query(
                    IndexName=GSI2_NAME,
                    KeyConditionExpression=Key("GSI2_PK").eq(gsi2_pk),
                    ProjectionExpression="PK, SK, fileURL, thumbURL, uploadedAt"
                )
                items = resp.get("Items", [])
                if not items:
                    result_status = "NotFound"
                    raise Exception("Skip further processing")

                # We expect exactly one match
                metadata_item = items[0]
                file_sk  = metadata_item["SK"]
                user_pk  = metadata_item["PK"]

            elif path.startswith("upload-files/"):
                url_type = "upload"
                upload_key = path                         # e.g. "upload-files/abc123.jpg"

                # 2b. Scan Metadata table for fileURL == url (only way since no direct GSI on fileURL)
                resp = metadata_table.scan(
                    FilterExpression=Attr("fileURL").eq(url),
                    ProjectionExpression="PK, SK, fileURL, thumbURL, uploadedAt"
                )
                items = resp.get("Items", [])
                if not items:
                    result_status = "NotFound"
                    raise Exception("Skip further processing")

                metadata_item = items[0]
                file_sk  = metadata_item["SK"]
                user_pk  = metadata_item["PK"]

            else:
                # URL does not live under either "thumbnails/" or "upload-files/"
                result_status = "NotFound"
                raise Exception("Skip further processing")


            # 2d. Fetch the current tags map from the Metadata item
            full_meta = metadata_table.get_item(Key={"PK": user_pk, "SK": file_sk})
            if "Item" not in full_meta:
                result_status = "NotFound"
                raise Exception("Skip further processing")

            md_item      = full_meta["Item"]
            current_tags = md_item.get("tags", {})  # e.g. { "Crow": 2, "Pigeon": 1 }

            # 2e. Apply add/remove for each (species, delta)
            changed_species = {}
            for species, delta in parsed_tags.items():
                old_count = current_tags.get(species, 0)
                if operation == 1:
                    # ADD
                    new_count = old_count + delta
                    current_tags[species] = new_count
                    changed_species[species] = (old_count, new_count)

                else:
                    # REMOVE
                    if old_count < delta:
                        # Cannot remove more tags than exist
                        result_status = "TagNotFound"
                        raise Exception("Skip further processing")

                    new_count = old_count - delta
                    if new_count > 0:
                        current_tags[species] = new_count
                        changed_species[species] = (old_count, new_count)
                    else:
                        # new_count == 0: delete the key entirely
                        current_tags.pop(species, None)
                        changed_species[species] = (old_count, 0)

            # 2f. Update DynamoDB Metadata item’s `tags` attribute
            metadata_table.update_item(
                Key={"PK": user_pk, "SK": file_sk},
                UpdateExpression="SET tags = :t",
                ExpressionAttributeValues={":t": current_tags}
            )

            # 2g. For each changed species, update or delete from TagIndex
            for species, (old_cnt, new_cnt) in changed_species.items():
                tag_pk = f"TAG#{species}"
                if operation == 1:
                    # ADD: put_item (overwrite or insert) with new tag count
                    tag_index_table.put_item(
                        Item={
                            "PK":         tag_pk,
                            "SK":          file_sk,
                            "fileURL":     md_item["fileURL"],
                            "thumbURL":    md_item.get("thumbURL", None),
                            "tagCount":    new_cnt,
                            "uploadedAt":  md_item["uploadedAt"],
                            "userPK":      user_pk
                        }
                    )
                else:
                    # REMOVE
                    if new_cnt == 0:
                        # Delete the TagIndex row entirely
                        tag_index_table.delete_item(Key={"PK": tag_pk, "SK": file_sk})
                    else:
                        # Just update tagCount
                        tag_index_table.update_item(
                            Key={"PK": tag_pk, "SK": file_sk},
                            UpdateExpression="SET tagCount = :c",
                            ExpressionAttributeValues={":c": new_cnt}
                        )

        except Exception as exc:
            # Only log if it wasn’t our “Skip further processing” signal
            if not str(exc).startswith("Skip further processing"):
                logger.exception(f"Error processing URL '{url}': {exc}")

            updated_results.append({"url": url, "status": result_status})
            continue

        # If we reach here with no exception, status remains "OK"
        updated_results.append({"url": url, "status": result_status})

    # 3. Return the bulk‐update results
    return {
        "statusCode": 200,
        "body": json.dumps({ "updated": updated_results }),
        "headers": { "Content-Type": "application/json", 
                    'Access-Control-Allow-Origin' : '*',                      
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
                     'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token' }
    }