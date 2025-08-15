# Module 1: Enumeration and Discovery
# Creates modeldata-dev and modeldata-prod buckets with intentional misconfigurations

resource "google_storage_bucket" "modeldata-dev" {
  name          = "modeldata-dev-${var.project_id}"
  location      = var.region
  force_destroy = true
  
  uniform_bucket_level_access = true
}

resource "google_storage_bucket" "modeldata-prod" {
  name          = "modeldata-prod-${var.project_id}"
  location      = var.region
  force_destroy = true
  
  uniform_bucket_level_access = true
}

resource "google_service_account" "bucket-service-account" {
  account_id   = "bucket-service-account"
  display_name = "Bucket Service Account"
  description  = "Service account for accessing model storage buckets"
}

# Grant dev bucket access
resource "google_storage_bucket_iam_member" "dev-bucket-access" {
  bucket = google_storage_bucket.modeldata-dev.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.bucket-service-account.email}"
}

# Grant prod bucket access (the vulnerability)
resource "google_storage_bucket_iam_member" "prod-bucket-access" {
  bucket = google_storage_bucket.modeldata-prod.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.bucket-service-account.email}"
}

# Create service account key
resource "google_service_account_key" "bucket-sa-key" {
  service_account_id = google_service_account.bucket-service-account.name
}

# Student workshop service account with limited access
resource "google_service_account" "student-workshop" {
  account_id   = "student-workshop"
  display_name = "Student Workshop Account"
  description  = "Service account for workshop students with limited initial access"
}

# Grant student workshop account access to ONLY the dev bucket
resource "google_storage_bucket_iam_member" "student-dev-bucket-access" {
  bucket = google_storage_bucket.modeldata-dev.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.student-workshop.email}"
}

# Create service account key for student workshop
resource "google_service_account_key" "student-workshop-key" {
  service_account_id = google_service_account.student-workshop.name
}

# Custom role for remediation
resource "google_project_iam_custom_role" "dev-bucket-access" {
  role_id     = "DevBucketAccess"
  title       = "Dev Bucket Access"
  description = "Access to development bucket only"
  permissions = [
    "storage.buckets.get",
    "storage.objects.get",
    "storage.objects.list"
  ]
}

# Output for student workshop service account key
output "student_workshop_key" {
  value       = google_service_account_key.student-workshop-key.private_key
  sensitive   = true
  description = "Base64 encoded private key for student workshop service account"
}

# Output for student workshop email
output "student_workshop_email" {
  value       = google_service_account.student-workshop.email
  description = "Email of the student workshop service account"
}