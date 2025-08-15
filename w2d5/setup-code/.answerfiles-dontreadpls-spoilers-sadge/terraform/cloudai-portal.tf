# CloudAI Labs Portal - Web interface for all modules

# Archive the portal code
data "archive_file" "cloudai_portal" {
  type        = "zip"
  source_dir  = "${path.module}/cloudai-portal"
  output_path = "${path.module}/files/cloudai-portal.zip"
}

# Storage for the portal code
resource "google_storage_bucket_object" "cloudai_portal_code" {
  name   = "cloudai-portal.zip"
  bucket = google_storage_bucket.cloud-function-bucket.name
  source = data.archive_file.cloudai_portal.output_path
}

# CloudAI Portal Function
resource "google_cloudfunctions2_function" "cloudai_portal" {
  name        = "cloudai-portal"
  description = "CloudAI Labs web portal - provides browser interface for all modules"
  location    = var.region

  build_config {
    runtime     = "python39"
    entry_point = "cloudai_portal"
    source {
      storage_source {
        bucket = google_storage_bucket.cloud-function-bucket.name
        object = google_storage_bucket_object.cloudai_portal_code.name
      }
    }
  }

  service_config {
    max_instance_count = 100
    available_memory   = "256M"
    timeout_seconds    = 60

    environment_variables = {
      PROJECT_ID = var.project_id
      REGION     = var.region
      # API Keys (intentionally vulnerable)
      CLOUDAI_API_KEY   = "dev-key-12345"
      CLOUDAI_ADMIN_KEY = "admin-secret-key"
      # Link to monitoring function
      MONITORING_FUNCTION_URL = google_cloudfunctions2_function.function.service_config[0].uri
      # Flag values for module gating
      FLAG1 = var.flag1_module2_key
      FLAG2 = var.flag2_module3_key
      FLAG3 = var.flag3_module4_key
      FLAG4 = var.flag4_solve_module4
    }

    # Use default compute service account (intentionally over-privileged)
    service_account_email = data.google_service_account.compute-account-module3.email
  }
}


# Allow public access to the portal
resource "google_cloud_run_service_iam_member" "cloudai_portal_public" {
  project  = google_cloudfunctions2_function.cloudai_portal.project
  location = google_cloudfunctions2_function.cloudai_portal.location
  service  = google_cloudfunctions2_function.cloudai_portal.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Output the portal URL
output "cloudai_portal_url" {
  value       = google_cloudfunctions2_function.cloudai_portal.service_config[0].uri
  description = "URL for the CloudAI Labs web portal"
}

# Output flag values for debugging (non-sensitive)
output "flag_configuration" {
  value = {
    flag1_value = var.flag1_module2_key
    flag2_value = var.flag2_module3_key
    flag3_value = var.flag3_module4_key
    flag4_value = var.flag4_solve_module4
  }
  description = "Flag values configured for module gating"
  sensitive   = true
}
