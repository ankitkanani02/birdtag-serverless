# BirdTag Serverless Application

A serverless system on AWS allowing users to upload images/audio/video of birds, auto-tag species with a pretrained model, search by tags, manage tags in bulk, and subscribe to email notifications for new sightings.

## Repo Contents

- `lambda_search_tags.py`           – Implements **Search Files by Tags** (`GET /files/search`)
- `lambda_fullsize_lookup.py`       – Implements **Get Full-Size URL** (`GET /files/fullsize`)
- `lambda_query_by_file.py`         – Implements **Find Similar Files** (`POST /files/query`)
- `lambda_manage_tags.py`           – Implements **Bulk Manage Tags** (`POST /files/tags/manage`)
- `lambda_subscriptions.py`         – Implements **Subscribe to Notifications** (`POST /notifications/subscribe`)
- `lambda_inference.py`             – Inference Lambda that tags new uploads and publishes SNS notifications
- `infra/`                          – Infrastructure-as-Code (Serverless/Terraform/SAM) defining APIs, DynamoDB tables, SNS topic, and Lambdas
- `requirements.txt`                – Python dependencies for all Lambdas
- `README.md`                       – This file

## My Contributions

- **API Design & Implementation**  
  Configured ** REST endpoints** in API Gateway, one per use-case: search, full-size lookup, on-the-fly query, bulk tag management, file-based search, and email subscriptions.

- **Lambda Handlers**  
  Authored all **6 Python Lambdas**, each wired to its API endpoint:
  - `lambda_search_tags.py`
  - `lambda_fullsize_lookup.py`
  - `lambda_query_by_file.py`
  - `lambda_manage_tags.py`
  - `lambda_subscriptions.py`
  - `lambda_inference.py`

- **Database Schema**  
  Defined three DynamoDB tables with appropriate primary keys and GSIs:
  1. **BirdTagMetadata-DDB** (main metadata)
  2. **BirdTagTagIndex** (inverted tag index)
  3. **BirdTagSubscriptions** (SNS subscription registry)

- **Security**  
  Secured all APIs with a **Cognito Authorizer** so only authenticated users can call them.

- **Notifications Integration**  
  Coordinated with the team to integrate **AWS SNS** using a single topic + filter policies, enabling per-species email alerts for subscribers.

## Deployment & Testing

1. Invoke endpoints via Postman, passing a Cognito JWT in `Authorization: Bearer <token>`.
4. Confirm DynamoDB tables and SNS topic in the AWS Console.

---

Made by **Ankit Kanani** (Student ID: 34552162), Monash University FIT5225, June 2025.  