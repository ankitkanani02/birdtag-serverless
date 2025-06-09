
# import os
# import json
# import logging
# import boto3
# from boto3.dynamodb.conditions import Key, Attr

# # Configure logger
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

# # Environment variables
# TAG_INDEX_TABLE = os.environ['TAG_INDEX_TABLE']      # e.g. "BirdTagTagIndex"
# # If you ever need to double-check fileType via the metadata table, set METADATA_TABLE
# # METADATA_TABLE = os.environ.get('METADATA_TABLE')

# dynamodb = boto3.resource('dynamodb')
# tag_index_table = dynamodb.Table(TAG_INDEX_TABLE)

# def lambda_handler(event, context):
#     """
#     Handles:
#       - GET /search?species=<species>         → single‐species (count ≥ 1)
#       - GET /search?tag1=<s1>&count1=<n1>&tag2=<s2>&count2=<n2>&…
#     Returns JSON:
#       {
#         "links": [
#           {
#             "fileURL": "<original_s3_url>",
#             "thumbURL": "<thumbnail_s3_url_or_null>"
#           },
#           ...
#         ]
#       }
    
#     Behavior changes vs. prior version:
#       • Previously, we returned a single URL per match (thumb if available, else fileURL).
#       • Now, for each match:
#           – If it’s an image: return both "fileURL" and "thumbURL".
#           – If it’s audio/video (no thumbnail exists): return "fileURL" and set "thumbURL": null.
#     """

#     # 1. Extract query params
#     params = event.get('queryStringParameters') or {}

#     # 2. Build list of (species, count)
#     species = params.get('species')
#     tags = []
#     if species:
#         tags = [(species, 1)]
#     else:
#         idx = 1
#         while True:
#             t_key = f"tag{idx}"
#             c_key = f"count{idx}"
#             if t_key in params and c_key in params:
#                 try:
#                     cnt = int(params[c_key])
#                 except ValueError:
#                     return {
#                         'statusCode': 400,
#                         'body': json.dumps({ "error": f"Invalid count{idx} value" }),
#                         'headers': { 'Content-Type': 'application/json',
#                         'Access-Control-Allow-Origin': '*',
#                         'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#                         'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#                         }
#                     }
#                 tags.append((params[t_key], cnt))
#                 idx += 1
#             else:
#                 break

#     if not tags:
#         return {
#             'statusCode': 400,
#             'body': json.dumps({ "error": "At least one species or tag/count pair is required" }),
#             'headers': { 'Content-Type': 'application/json',
#             'Access-Control-Allow-Origin': '*',
#             'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#             'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#             }
#         }

#     # 3. For each (species, count), query the TagIndex table to collect SKs and URL mapping
#     sk_sets       = []
#     sk_to_fileURL = {}  # SK -> original fileURL
#     sk_to_thumbURL= {}  # SK -> thumbnail URL (or None)
#     sk_to_ts      = {}  # SK -> uploadedAt timestamp

#     for (sp, ct) in tags:
#         pk_val = f"TAG#{sp}"
#         logger.info(f"Querying TagIndex table '{TAG_INDEX_TABLE}' for PK={pk_val}")

#         try:
#             resp = tag_index_table.query(
#                 KeyConditionExpression = Key('PK').eq(pk_val),
#                 # Only keep items with tagCount ≥ requested count:
#                 FilterExpression       = Attr('tagCount').gte(ct),
#                 ProjectionExpression   = "SK, fileURL, thumbURL, tagCount, uploadedAt"
#             )
#         except Exception as e:
#             logger.error(f"TagIndex query failed for species='{sp}': {e}")
#             return {
#                 'statusCode': 500,
#                 'body': json.dumps({ "error": f"TagIndex query failed for '{sp}'" }),
#                 'headers': { 'Content-Type': 'application/json',
#                 'Access-Control-Allow-Origin': '*',
#                 'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#                 'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#                 }
#             }

#         items = resp.get('Items', [])
#         if not items:
#             # No files match this species+count
#             logger.info(f"No TagIndex items found for PK={pk_val} with tagCount>= {ct}")
#             return {
#                 'statusCode': 200,
#                 'body': json.dumps({ "links": [] }),
#                 'headers': { 'Content-Type': 'application/json',
#                 'Access-Control-Allow-Origin': '*',
#                 'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#                 'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#                 }
#             }

#         current_sk_set = set()
#         for it in items:
#             sk = it['SK']
#             current_sk_set.add(sk)

#             # Record uploadedAt timestamp (once per SK)
#             if sk not in sk_to_ts:
#                 sk_to_ts[sk] = it['uploadedAt']

#             # Always record fileURL
#             if sk not in sk_to_fileURL:
#                 sk_to_fileURL[sk] = it['fileURL']

#             # Record thumbURL if present; else explicitly set to None
#             if sk not in sk_to_thumbURL:
#                 sk_to_thumbURL[sk] = it.get('thumbURL') if it.get('thumbURL') else None

#         sk_sets.append(current_sk_set)

#     # 4. Compute the intersection across all tag SK sets (logical AND)
#     common_sks = set.intersection(*sk_sets)
#     if not common_sks:
#         logger.info("Intersection of SK sets is empty; returning no links.")
#         return {
#             'statusCode': 200,
#             'body': json.dumps({ "links": [] }),
#             'headers': { 'Content-Type': 'application/json',
#             'Access-Control-Allow-Origin': '*',
#             'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#             'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#             }
#         }

#     # 5. Sort SKs by uploadedAt descending (newest first)
#     sorted_sks = sorted(
#         common_sks,
#         key=lambda sk: sk_to_ts.get(sk, ""),
#         reverse=True
#     )

#     # 6. Build the final "links" array. For each SK, include both fileURL and thumbURL (which may be None).
#     links = []
#     for sk in sorted_sks:
#         entry = {
#             "fileURL":  sk_to_fileURL.get(sk),
#             "thumbURL": sk_to_thumbURL.get(sk)   # None if no thumbnail exists
#         }
#         links.append(entry)

#     logger.info(f"Returning {len(links)} link‐objects.")
#     return {
#         'statusCode': 200,
#         'body': json.dumps({ "links": links }),
#         'headers': { 'Content-Type': 'application/json',
#         'Access-Control-Allow-Origin': '*',
#         'Access-Control-Allow-Headers': 'Content-Type,Authorization',
#         'Access-Control-Allow-Methods': 'GET,OPTIONS' 
#         }
# }


import os
import json
import logging
import boto3
import base64
import tempfile
import mimetypes
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─── Environment Variables ───────────────────────────────────────────────────
TAG_INDEX_TABLE_NAME = os.environ.get("TAG_INDEX_TABLE_NAME", "BirdTagTagIndex")
METADATA_TABLE_NAME  = os.environ.get("METADATA_TABLE_NAME", "BirdTagMetadata-DDB")
BIRD_LAMBDA_ARN      = os.environ.get("BIRD_LAMBDA_ARN", "")
TEMP_BUCKET          = os.environ.get("UPLOAD_BUCKET", "")

# ─── AWS clients ─────────────────────────────────────────────────────────────
dynamodb        = boto3.resource("dynamodb")
tag_index_table = dynamodb.Table(TAG_INDEX_TABLE_NAME)
metadata_table  = dynamodb.Table(METADATA_TABLE_NAME)
lambda_client   = boto3.client("lambda")
s3_client       = boto3.client("s3")

def lambda_handler(event, context):
    """
    Main Lambda handler that supports:
    1. OPTIONS requests for CORS
    2. Direct file upload (multipart/form-data or base64)
    3. S3 bucket/key processing
    """
    
    # CORS headers for all responses
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE',
        'Content-Type': 'application/json'
    }
    
    # Handle OPTIONS request for CORS preflight
    http_method = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': ''
        }
    
    try:
        # Check request type based on content-type and body structure
        content_type = event.get('headers', {}).get('content-type', '') or event.get('headers', {}).get('Content-Type', '')
        
        logger.info(f"Content-Type: {content_type}")
        logger.info(f"Event keys: {list(event.keys())}")
        
        # Determine request type
        if 'multipart/form-data' in content_type:
            # Direct file upload via multipart form data
            return handle_multipart_upload(event, cors_headers)
        elif event.get('body') and is_json_body(event.get('body', '')):
            # JSON request (could be S3 bucket/key or base64 file)
            return handle_json_request(event, cors_headers)
        else:
            # Try to handle as base64 encoded file in body
            return handle_base64_upload(event, cors_headers)
            
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Internal Server Error: {str(e)}"}),
            "headers": cors_headers
        }

def is_json_body(body_str):
    """Check if body is valid JSON"""
    try:
        json.loads(body_str)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def handle_json_request(event, cors_headers):
    """Handle JSON requests (S3 bucket/key or base64 file)"""
    try:
        body = json.loads(event["body"])
        
        # Check if it's S3 bucket/key request
        if "bucket" in body and "key" in body:
            return handle_s3_file_request(body, cors_headers)
        
        # Check if it's base64 file request
        elif "fileB64" in body:
            return handle_base64_file_request(body, cors_headers)
        
        else:
            raise ValueError("Invalid JSON format. Expected 'bucket'/'key' or 'fileB64'")
            
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid JSON in request body"}),
            "headers": cors_headers
        }
    except Exception as e:
        logger.error(f"Error in handle_json_request: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": str(e)}),
            "headers": cors_headers
        }

def handle_multipart_upload(event, cors_headers):
    """Handle multipart form data upload"""
    try:
        # API Gateway encodes multipart data as base64
        body = event.get('body', '')
        is_base64 = event.get('isBase64Encoded', False)
        
        if is_base64:
            # Decode base64 body
            body_bytes = base64.b64decode(body)
        else:
            body_bytes = body.encode('utf-8')
        
        # Parse multipart data (simplified - in production use a proper parser)
        # For now, we'll extract the file data from the multipart body
        file_data = extract_file_from_multipart(body_bytes)
        
        if not file_data:
            raise ValueError("No file found in multipart data")
        
        # Determine file extension from content type or default
        content_type = event.get('headers', {}).get('content-type', '')
        file_ext = get_extension_from_content_type(content_type) or '.jpg'
        
        # Run inference
        tags = run_inference_on_file_data(file_data, file_ext)
        
        # Process tags and find matching files
        return process_tags_and_find_matches(tags, cors_headers)
        
    except Exception as e:
        logger.error(f"Error in handle_multipart_upload: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Multipart upload error: {str(e)}"}),
            "headers": cors_headers
        }

def handle_base64_upload(event, cors_headers):
    """Handle base64 encoded file in body"""
    try:
        body = event.get('body', '')
        is_base64 = event.get('isBase64Encoded', False)
        
        if is_base64:
            file_data = base64.b64decode(body)
        else:
            # Try to decode as base64 anyway
            try:
                file_data = base64.b64decode(body)
            except:
                raise ValueError("Body is not valid base64")
        
        # Default to jpg if we can't determine type
        file_ext = '.jpg'
        
        # Run inference
        tags = run_inference_on_file_data(file_data, file_ext)
        
        # Process tags and find matching files
        return process_tags_and_find_matches(tags, cors_headers)
        
    except Exception as e:
        logger.error(f"Error in handle_base64_upload: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Base64 upload error: {str(e)}"}),
            "headers": cors_headers
        }

def handle_base64_file_request(body, cors_headers):
    """Handle base64 file in JSON request"""
    try:
        file_b64 = body.get("fileB64")
        filename = body.get("filename", "upload.bin")
        content_type = body.get("contentType")
        
        # Decode base64 file
        file_data = base64.b64decode(file_b64)
        
        # Determine file extension
        file_ext = (
            os.path.splitext(filename)[1] or
            get_extension_from_content_type(content_type or "") or
            ".bin"
        )
        
        # Run inference
        tags = run_inference_on_file_data(file_data, file_ext)
        
        # Process tags and find matching files
        return process_tags_and_find_matches(tags, cors_headers)
        
    except Exception as e:
        logger.error(f"Error in handle_base64_file_request: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": str(e)}),
            "headers": cors_headers
        }

def handle_s3_file_request(body, cors_headers):
    """Handle S3 bucket/key request (your original logic)"""
    try:
        bucket = body.get("bucket")
        key = body.get("key")
        
        if not bucket or not key:
            raise ValueError("Missing 'bucket' or 'key' in request body")
        
        if bucket != TEMP_BUCKET:
            raise ValueError(f"Invalid bucket '{bucket}'. Expected '{TEMP_BUCKET}'")
        
        # Invoke inference Lambda to get tags
        detected_tags = invoke_inference_lambda_s3(bucket, key)
        
        if not detected_tags:
            # No tags → delete temp upload & return empty list
            delete_s3_object(bucket, key)
            return {
                "statusCode": 200,
                "body": json.dumps({"links": []}),
                "headers": cors_headers
            }
        
        # Find matching files
        final_links = find_matching_files(detected_tags)
        
        # Delete the temporary S3 object
        delete_s3_object(bucket, key)
        
        return {
            "statusCode": 200,
            "body": json.dumps({"links": final_links}),
            "headers": cors_headers
        }
        
    except Exception as e:
        logger.error(f"Error in handle_s3_file_request: {e}")
        # Clean up temp upload if we have bucket/key
        try:
            if "bucket" in locals() and "key" in locals():
                delete_s3_object(bucket, key)
        except:
            pass
        return {
            "statusCode": 400,
            "body": json.dumps({"error": str(e)}),
            "headers": cors_headers
        }

def extract_file_from_multipart(body_bytes):
    """
    Simple multipart parser to extract file data.
    In production, use a proper multipart parser library.
    """
    try:
        # Look for file boundary and extract binary data
        body_str = body_bytes.decode('utf-8', errors='ignore')
        
        # Find the start of file data (after Content-Type header)
        lines = body_str.split('\n')
        file_start_idx = -1
        
        for i, line in enumerate(lines):
            if 'Content-Type:' in line and ('image/' in line or 'audio/' in line or 'video/' in line):
                # File data starts after the next empty line
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() == '':
                        file_start_idx = j + 1
                        break
                break
        
        if file_start_idx > 0:
            # Extract binary data from the remaining lines
            file_lines = lines[file_start_idx:]
            # Remove boundary markers
            file_lines = [line for line in file_lines if not line.startswith('--')]
            file_data_str = '\n'.join(file_lines)
            
            # Try to decode as base64 if it looks like base64
            try:
                return base64.b64decode(file_data_str)
            except:
                # If not base64, return as bytes
                return file_data_str.encode('latin1')
        
        # Fallback: try to extract any base64-looking data
        import re
        base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        matches = re.findall(base64_pattern, body_str)
        if matches:
            try:
                return base64.b64decode(matches[0])
            except:
                pass
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting file from multipart: {e}")
        return None

def get_extension_from_content_type(content_type):
    """Get file extension from content type"""
    if not content_type:
        return None
    
    # Remove parameters like boundary
    main_type = content_type.split(';')[0].strip()
    
    extension_map = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp',
        'audio/mpeg': '.mp3',
        'audio/wav': '.wav',
        'audio/flac': '.flac',
        'video/mp4': '.mp4',
        'video/avi': '.avi',
        'video/quicktime': '.mov'
    }
    
    return extension_map.get(main_type) or mimetypes.guess_extension(main_type)

def run_inference_on_file_data(file_data, file_ext):
    """Run inference on file data using your existing inference logic"""
    try:
        # Use your existing run_inference_on_bytes function
        # This should be imported from your inference module
        
        # For now, mock the inference result
        # Replace this with actual inference call
        mock_tags = [{"Crow": 1}]  # Mock result
        
        # If you have the inference function available, use it:
        # from your_inference_module import run_inference_on_bytes
        # tags = run_inference_on_bytes(file_data, file_ext)
        
        return mock_tags
        
    except Exception as e:
        logger.error(f"Error in inference: {e}")
        return []

def process_tags_and_find_matches(tags, cors_headers):
    """Process inference tags and find matching files"""
    try:
        # Convert tags from list of dicts to single dict
        detected_tags = {}
        for tag_dict in tags:
            detected_tags.update(tag_dict)
        
        if not detected_tags:
            return {
                "statusCode": 200,
                "body": json.dumps({"links": []}),
                "headers": cors_headers
            }
        
        # Find matching files
        final_links = find_matching_files(detected_tags)
        
        return {
            "statusCode": 200,
            "body": json.dumps({"links": final_links}),
            "headers": cors_headers
        }
        
    except Exception as e:
        logger.error(f"Error processing tags: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
            "headers": cors_headers
        }

def find_matching_files(detected_tags):
    """Find files that match the detected tags"""
    try:
        # Query TagIndex for each species
        per_species_maps = []
        for species, count_required in detected_tags.items():
            sk_map = query_tag_index(species, count_required)
            if not sk_map:
                # If any species has zero matches, intersection is empty
                return []
            per_species_maps.append(sk_map)
        
        # Intersect SK sets
        sk_sets = [set(m.keys()) for m in per_species_maps]
        intersected_sks = set.intersection(*sk_sets)
        
        if not intersected_sks:
            return []
        
        # Build final_links
        final_links = []
        reference_map = per_species_maps[0]
        for sk in intersected_sks:
            info = reference_map[sk]
            file_url = info.get("fileURL")
            thumb_url = info.get("thumbURL")
            final_links.append({
                "fileURL": file_url, 
                "thumbURL": thumb_url
            })
        
        return final_links
        
    except Exception as e:
        logger.error(f"Error finding matching files: {e}")
        return []

def invoke_inference_lambda_s3(bucket: str, key: str) -> dict:
    """
    Invoke the Inference Lambda via S3-triggered path, passing {bucket, key, skipDb: True}.
    Returns a dict of detected tags, e.g. {"Crow": 2, "Sparrow": 1}, or {} if none.
    """
    if not BIRD_LAMBDA_ARN:
        logger.warning("BIRD_LAMBDA_ARN not configured, using mock data")
        return {'Crow': 1}  # Mock result
    
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
    results = body_json.get("results", [])
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
            "fileURL": item.get("fileURL"),
            "userPK": item.get("userPK"),
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
                "fileURL": item.get("fileURL"),
                "userPK": item.get("userPK"),
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
    Delete the temporary S3 object so we don't store it permanently.
    """
    try:
        s3_client.delete_object(Bucket=bucket, Key=key)
        logger.info(f"Deleted temporary S3 object: {bucket}/{key}")
    except ClientError as e:
        logger.error(f"Failed to delete S3 object {bucket}/{key}: {e}")