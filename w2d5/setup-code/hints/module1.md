# Module 1: Enumeration and Discovery

## Introduction

Welcome to CloudAI Labs! You've been given access to our development model storage bucket to help with testing. The bucket name is `modeldata-dev-$PROJECT_ID`.

We keep our development and production environments strictly separated... or do we?

## Your Goal

**Find CloudAI's secret GPT-6 benchmark results that were supposedly leaked**

## Useful commands and tools:

- `gsutil ls gs://bucket-name/` - List bucket contents
- `gsutil cp gs://bucket-name/file local-file` - Download files
- `gcloud auth activate-service-account --key-file=KEY_FILE` - Use service account credentials

## Hints
<details>
  <summary>Hint 1</summary>

  Start by exploring the development bucket you were given access to.  
  Are there any interesting files? Perhaps some credentials?
  
  ```bash
  gsutil ls gs://modeldata-dev-$PROJECT_ID/
  ```

</details>

<details>
  <summary>Hint 2</summary>

  That service account JSON file looks interesting! Download it and see what it can access.
  
  ```bash
  gsutil cp gs://modeldata-dev-$PROJECT_ID/bucket-service-account.json .
  gcloud auth activate-service-account --key-file=bucket-service-account.json
  gsutil ls
  ```

</details>

<details>
  <summary>Hint 3</summary>

  Service accounts often have access to more than intended. CloudAI uses predictable naming patterns.  
  If there's a dev bucket, what about a prod bucket?
  
  Try: `gsutil ls gs://modeldata-prod-$PROJECT_ID/`

</details>