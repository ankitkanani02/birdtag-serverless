import os
import json
import logging
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─── Make sure these are defined under "Environment variables" in the Lambda console ───
TAG_INDEX_TABLE_NAME = os.environ["TAG_INDEX_TABLE_NAME"]    # e.g. "BirdTagTagIndex"
METADATA_TABLE_NAME  = os.environ["METADATA_TABLE_NAME"]     # e.g. "BirdTagMetadata-DDB"
BIRD_LAMBDA_ARN      = os.environ["BIRD_LAMBDA_ARN"]         # e.g. "arn:aws:lambda:us-east-1:123456789012:function:BirdTag-Inference"
TEMP_BUCKET          = os.environ["UPLOAD_BUCKET"]           # e.g. "birdtag-media-us-east-1-s3"

# ─── AWS clients ───────────────────────────────────────────────────────────────────
dynamodb        = boto3.resource("dynamodb")
tag_index_table = dynamodb.Table(TAG_INDEX_TABLE_NAME)
metadata_table  = dynamodb.Table(METADATA_TABLE_NAME)
lambda_client   = boto3.client("lambda")
s3_client       = boto3.client("s3")


def invoke_inference_lambda_s3(bucket: str, key: str) -> dict:
    """
    Invoke the Inference Lambda via S3-triggered path, passing {bucket, key, skipDb: True}.
    Returns a dict of detected tags, e.g. {"Crow": 2, "Sparrow": 1}, or {} if none.
    """
    payload = {"bucket": bucket, "key": key, "skipDb": True}

    try:
        resp = lambda_client.invoke(
            FunctionName=BIRD_LAMBDA_ARN,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        logger.error(f"Failed to invoke Inference Lambda: {e}")
        raise

    result = json.load(resp["Payload"])
    status = result.get("statusCode", 500)
    if status != 200:
        body_text = result.get("body", "")
        logger.error(f"Inference Lambda returned {status}: {body_text}")
        raise RuntimeError(f"Inference Lambda error ({status}): {body_text}")

    body_json = json.loads(result["body"])
    results   = body_json.get("results", [])
    if not results or "tags" not in results[0]:
        return {}

    # Convert list-of-dicts to a single dict
    detected = {}
    for tag_dict in results[0]["tags"]:
        for species, cnt in tag_dict.items():
            try:
                detected[species] = int(cnt)
            except (ValueError, TypeError):
                detected[species] = 1

    logger.info(f"Detected tags from inference: {detected}")
    return detected


def query_tag_index(species: str, count_required: int) -> dict:
    """
    Query BirdTagTagIndex for PK="TAG#<species>" and tagCount >= count_required.
    Returns a map SK → { thumbURL, fileURL, userPK, tagCount }.
    """
    pk_val = f"TAG#{species}"
    sk_map = {}

    try:
        response = tag_index_table.query(
            KeyConditionExpression=Key("PK").eq(pk_val),
            FilterExpression=Attr("tagCount").gte(count_required),
            ProjectionExpression="SK, thumbURL, fileURL, userPK, tagCount"
        )
    except ClientError as e:
        logger.error(f"DynamoDB query error for {pk_val}: {e}")
        raise

    for item in response.get("Items", []):
        sk_map[item["SK"]] = {
            "thumbURL": item.get("thumbURL"),
            "fileURL":  item.get("fileURL"),
            "userPK":   item.get("userPK"),
            "tagCount": item.get("tagCount"),
        }

    # Handle pagination
    while "LastEvaluatedKey" in response:
        try:
            response = tag_index_table.query(
                KeyConditionExpression=Key("PK").eq(pk_val),
                FilterExpression=Attr("tagCount").gte(count_required),
                ProjectionExpression="SK, thumbURL, fileURL, userPK, tagCount",
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
        except ClientError as e:
            logger.error(f"DynamoDB pagination error for {pk_val}: {e}")
            raise

        for item in response.get("Items", []):
            sk_map[item["SK"]] = {
                "thumbURL": item.get("thumbURL"),
                "fileURL":  item.get("fileURL"),
                "userPK":   item.get("userPK"),
                "tagCount": item.get("tagCount"),
            }

    return sk_map


def get_file_type_from_metadata(user_pk: str, sk: str) -> str:
    """
    Look up "fileType" (image|video|audio) in the BirdTagMetadata-DDB table.
    """
    try:
        resp = metadata_table.get_item(Key={"PK": user_pk, "SK": sk})
    except ClientError as e:
        logger.error(f"DynamoDB get_item error for {user_pk}/{sk}: {e}")
        raise

    item = resp.get("Item")
    return item.get("fileType") if item else None


def delete_s3_object(bucket: str, key: str):
    """
    Delete the temporary S3 object so we don’t store it permanently.
    """
    try:
        s3_client.delete_object(Bucket=bucket, Key=key)
        logger.info(f"Deleted temporary S3 object: {bucket}/{key}")
    except ClientError as e:
        logger.error(f"Failed to delete S3 object {bucket}/{key}: {e}")


def lambda_handler(event, context):
    """
    1) Parse JSON body for { "bucket": str, "key": str }.
    2) Invoke the inference Lambda (skipDb=True) to get detected_tags.
    3) If detected_tags is empty, delete temp S3 object & return { "links": [] }.
    4) Otherwise, query TagIndex for each species, intersect SKs, build final_links.
    5) Delete temp S3 object and return { "links": [...] }.
    """
    try:
        # ─── Step 1: Parse request body ───────────────────────────────────────
        if not event.get("body"):
            raise ValueError("Request body is empty. Expecting JSON with 'bucket' and 'key'.")
        body = json.loads(event["body"])

        bucket = body.get("bucket")
        key    = body.get("key")
        if not bucket or not key:
            raise ValueError("Missing 'bucket' or 'key' in request body.")

        # Make sure they didn’t point to the wrong bucket
        if bucket != TEMP_BUCKET:
            raise ValueError(f"Invalid bucket '{bucket}'. Expected '{TEMP_BUCKET}'.")

        # ─── Step 2: Invoke Inference Lambda to get tags ───────────────────────
        detected_tags = invoke_inference_lambda_s3(bucket, key)
        if not detected_tags:
            # No tags → delete temp upload & return empty list
            delete_s3_object(bucket, key)
            return {
                "statusCode": 200,
                "body": json.dumps({"links": []}),
                "headers": {"Content-Type": "application/json",  'Access-Control-Allow-Origin' : '*',                       
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
            }

        # ─── Step 3: For each species, query TagIndex ────────────────────────
        per_species_maps = []
        for species, count_required in detected_tags.items():
            sk_map = query_tag_index(species, count_required)
            if not sk_map:
                # If any species has zero matches, intersection is empty
                delete_s3_object(bucket, key)
                return {
                    "statusCode": 200,
                    "body": json.dumps({"links": []}),
                    "headers": {"Content-Type": "application/json",  'Access-Control-Allow-Origin' : '*',                       
                    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
                }
            per_species_maps.append(sk_map)

        # ─── Step 4: Intersect SK sets ───────────────────────────────────────
        sk_sets = [set(m.keys()) for m in per_species_maps]
        intersected_sks = set.intersection(*sk_sets)
        if not intersected_sks:
            delete_s3_object(bucket, key)
            return {
                "statusCode": 200,
                "body": json.dumps({"links": []}),
                "headers": {"Content-Type": "application/json",  'Access-Control-Allow-Origin' : '*',                       
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
            }

        # ─── Step 5: Build final_links ────────────────────────────────────────
        final_links = []
        # We only need the first species map to look up URLs
        reference_map = per_species_maps[0]
        for sk in intersected_sks:
            info    = reference_map[sk]
            user_pk = info.get("userPK")

            # (Optional) Get fileType, if you need to treat images vs. videos differently:
            _ = get_file_type_from_metadata(user_pk, sk)

            file_url  = info.get("fileURL")
            thumb_url = info.get("thumbURL")
            final_links.append({"fileURL": file_url, "thumbURL": thumb_url})

        # ─── Step 6: Delete the S3 object ─────────────────────────────────────
        delete_s3_object(bucket, key)

        # ─── Step 7: Return the results ───────────────────────────────────────
        return {
            "statusCode": 200,
            "body": json.dumps({"links": final_links}),
            "headers": {"Content-Type": "application/json",  'Access-Control-Allow-Origin' : '*',                       
                        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
        }

    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        # Clean up temp upload if we have a bucket/key
        try:
            if "bucket" in locals() and "key" in locals():
                delete_s3_object(bucket, key)
        except:
            pass
        return {
            "statusCode": 400,
            "body": json.dumps({"error": str(ve)}),
            "headers": {"Content-Type": "application/json",  
                        'Access-Control-Allow-Origin' : '*',                       
                        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
        }

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        # Clean up temp upload if we have a bucket/key
        try:
            if "bucket" in locals() and "key" in locals():
                delete_s3_object(bucket, key)
        except:
            pass
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Internal Server Error: {str(e)}"}),
            "headers": {"Content-Type": "application/json", 'Access-Control-Allow-Origin' : '*',                       
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'}
        }