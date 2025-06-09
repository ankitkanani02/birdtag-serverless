import os
import json
import logging
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─── Environment Variables ───────────────────────────
SUBSCRIPTIONS_TABLE = os.environ["SUBSCRIPTIONS_TABLE"]
SNS_TOPIC_PREFIX    = os.environ["SNS_TOPIC_PREFIX"]  # e.g. "BirdTagNotifications-"
SNS_TOPIC_ARN       = os.environ["SNS_TOPIC_ARN"]

# # ─── AWS Clients ──────────────────────────────────────
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
subs_table = dynamodb.Table(SUBSCRIPTIONS_TABLE)

def lambda_handler(event, context):
    """
    POST /subscriptions
    Body: { "species": "...", "email": "user@example.com" }
    Uses a single SNS topic with filter policies so that a single email
    can subscribe to multiple species.
    """
    # 1. Parse & validate input
    try:
        body    = json.loads(event.get("body") or "{}")
        species = body["species"].strip()
        email   = body["email"].strip().lower()
        if not species or "@" not in email:
            raise ValueError("Invalid species or email")
    except Exception as e:
        logger.error(f"Invalid input: {e}")
        return _response(400, {"error": "Request must include valid 'species' and 'email'"})

    # Prepare this species filter policy
    new_filter_policy = json.dumps({"species": [species]})

    # 2. Subscribe (or get) the email subscription
    try:
        resp = sns.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol="email",
            Endpoint=email,
            Attributes={"FilterPolicy": new_filter_policy},
            ReturnSubscriptionArn=True
        )
        subscription_arn = resp.get("SubscriptionArn")
        logger.info(f"sns.subscribe returned ARN={subscription_arn}")

    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = str(e)
        if code == "InvalidParameter" and "Subscription already exists" in msg:
            # subscription exists—find its ARN
            subscription_arn = _find_existing_subscription_arn(email)
            if not subscription_arn:
                logger.error("Could not find existing subscription ARN for %s", email)
                return _response(500, {"error": "SNS subscription lookup failed"})
        else:
            logger.exception("SNS subscribe error")
            return _response(500, {"error": "SNS subscribe error"})

    # 3. If confirmed ARN, merge filter policy
    if subscription_arn and subscription_arn.startswith("arn:aws:sns:"):
        try:
            attrs = sns.get_subscription_attributes(SubscriptionArn=subscription_arn)["Attributes"]
            existing = json.loads(attrs.get("FilterPolicy", "{}"))
            species_set = set(existing.get("species", []))
            species_set.add(species)
            merged_policy = json.dumps({"species": sorted(species_set)})
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicy",
                AttributeValue=merged_policy
            )
            logger.info("Merged filter policy for %s: %s", email, merged_policy)
        except ClientError as e:
            logger.exception("Failed to merge filter policy")
    else:
        logger.info("Subscription pending confirmation, skipping merge step")

    # 4. Persist subscription in DynamoDB
    now_iso = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    pk = f"SUB#{species}"
    sk = f"EMAIL#{email}"
    try:
        subs_table.put_item(Item={
            "PK":              pk,
            "SK":              sk,
            "subscribedAt":    now_iso,
            "subscriptionArn": subscription_arn or ""
        })
    except Exception:
        logger.exception("DynamoDB put_item failed")
        return _response(500, {"error": "DynamoDB error"})

    # 5. Return success
    return _response(200, {
        "species":         species,
        "email":           email,
        "subscriptionArn": subscription_arn,
        "subscribedAt":    now_iso
    })


def _find_existing_subscription_arn(email: str) -> str | None:
    """List subscriptions on the topic and return the ARN matching this email."""
    paginator = sns.get_paginator("list_subscriptions_by_topic")
    for page in paginator.paginate(TopicArn=SNS_TOPIC_ARN):
        for sub in page["Subscriptions"]:
            if sub["Protocol"] == "email" and sub["Endpoint"].lower() == email:
                return sub["SubscriptionArn"]
    return None


def _response(status_code: int, body: dict):
    """Helper to format HTTP response with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type":                "application/json",
            "Access-Control-Allow-Origin":   "*",
            "Access-Control-Allow-Headers":  "Content-Type,Authorization",
            "Access-Control-Allow-Methods":  "POST,OPTIONS"
        },
        "body": json.dumps(body)
    }