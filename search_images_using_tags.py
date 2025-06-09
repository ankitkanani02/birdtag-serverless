
import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
TAG_INDEX_TABLE = os.environ['TAG_INDEX_TABLE']      # e.g. "BirdTagTagIndex"
# If you ever need to double-check fileType via the metadata table, set METADATA_TABLE
# METADATA_TABLE = os.environ.get('METADATA_TABLE')

dynamodb = boto3.resource('dynamodb')
tag_index_table = dynamodb.Table(TAG_INDEX_TABLE)

def lambda_handler(event, context):
    """
    Handles:
      - GET /search?species=<species>         → single‐species (count ≥ 1)
      - GET /search?tag1=<s1>&count1=<n1>&tag2=<s2>&count2=<n2>&…
    Returns JSON:
      {
        "links": [
          {
            "fileURL": "<original_s3_url>",
            "thumbURL": "<thumbnail_s3_url_or_null>"
          },
          ...
        ]
      }
    
    Behavior changes vs. prior version:
      • Previously, we returned a single URL per match (thumb if available, else fileURL).
      • Now, for each match:
          – If it’s an image: return both "fileURL" and "thumbURL".
          – If it’s audio/video (no thumbnail exists): return "fileURL" and set "thumbURL": null.
    """

    # 1. Extract query params
    params = event.get('queryStringParameters') or {}

    # 2. Build list of (species, count)
    species = params.get('species')
    tags = []
    if species:
        tags = [(species, 1)]
    else:
        idx = 1
        while True:
            t_key = f"tag{idx}"
            c_key = f"count{idx}"
            if t_key in params and c_key in params:
                try:
                    cnt = int(params[c_key])
                except ValueError:
                    return {
                        'statusCode': 400,
                        'body': json.dumps({ "error": f"Invalid count{idx} value" }),
                        'headers': { 'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                        'Access-Control-Allow-Methods': 'GET,OPTIONS' 
                        }
                    }
                tags.append((params[t_key], cnt))
                idx += 1
            else:
                break

    if not tags:
        return {
            'statusCode': 400,
            'body': json.dumps({ "error": "At least one species or tag/count pair is required" }),
            'headers': { 'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,OPTIONS' 
            }
        }

    # 3. For each (species, count), query the TagIndex table to collect SKs and URL mapping
    sk_sets       = []
    sk_to_fileURL = {}  # SK -> original fileURL
    sk_to_thumbURL= {}  # SK -> thumbnail URL (or None)
    sk_to_ts      = {}  # SK -> uploadedAt timestamp

    for (sp, ct) in tags:
        pk_val = f"TAG#{sp}"
        logger.info(f"Querying TagIndex table '{TAG_INDEX_TABLE}' for PK={pk_val}")

        try:
            resp = tag_index_table.query(
                KeyConditionExpression = Key('PK').eq(pk_val),
                # Only keep items with tagCount ≥ requested count:
                FilterExpression       = Attr('tagCount').gte(ct),
                ProjectionExpression   = "SK, fileURL, thumbURL, tagCount, uploadedAt"
            )
        except Exception as e:
            logger.error(f"TagIndex query failed for species='{sp}': {e}")
            return {
                'statusCode': 500,
                'body': json.dumps({ "error": f"TagIndex query failed for '{sp}'" }),
                'headers': { 'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'GET,OPTIONS' 
                }
            }

        items = resp.get('Items', [])
        if not items:
            # No files match this species+count
            logger.info(f"No TagIndex items found for PK={pk_val} with tagCount>= {ct}")
            return {
                'statusCode': 200,
                'body': json.dumps({ "links": [] }),
                'headers': { 'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'GET,OPTIONS' 
                }
            }

        current_sk_set = set()
        for it in items:
            sk = it['SK']
            current_sk_set.add(sk)

            # Record uploadedAt timestamp (once per SK)
            if sk not in sk_to_ts:
                sk_to_ts[sk] = it['uploadedAt']

            # Always record fileURL
            if sk not in sk_to_fileURL:
                sk_to_fileURL[sk] = it['fileURL']

            # Record thumbURL if present; else explicitly set to None
            if sk not in sk_to_thumbURL:
                sk_to_thumbURL[sk] = it.get('thumbURL') if it.get('thumbURL') else None

        sk_sets.append(current_sk_set)

    # 4. Compute the intersection across all tag SK sets (logical AND)
    common_sks = set.intersection(*sk_sets)
    if not common_sks:
        logger.info("Intersection of SK sets is empty; returning no links.")
        return {
            'statusCode': 200,
            'body': json.dumps({ "links": [] }),
            'headers': { 'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,OPTIONS' 
            }
        }

    # 5. Sort SKs by uploadedAt descending (newest first)
    sorted_sks = sorted(
        common_sks,
        key=lambda sk: sk_to_ts.get(sk, ""),
        reverse=True
    )

    # 6. Build the final "links" array. For each SK, include both fileURL and thumbURL (which may be None).
    links = []
    for sk in sorted_sks:
        entry = {
            "fileURL":  sk_to_fileURL.get(sk),
            "thumbURL": sk_to_thumbURL.get(sk)   # None if no thumbnail exists
        }
        links.append(entry)

    logger.info(f"Returning {len(links)} link‐objects.")
    return {
        'statusCode': 200,
        'body': json.dumps({ "links": links }),
        'headers': { 'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,OPTIONS' 
        }
}