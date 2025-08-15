# Archive a single file.

# Archive a single file.

data "archive_file" "main" {
  # https://cloud.google.com/functions/docs/writing/specifying-dependencies-python#packaging_local_dependencies
  type        = "zip"
  source_dir  = "${path.module}/script"
  output_path = "${path.module}/files/main.zip"
}

data "google_service_account" "compute-account-module3" {
  account_id = format("%s-compute@developer.gserviceaccount.com", var.project_number)
}

resource "google_service_account" "monitoring-function" {
  account_id   = "monitoring-function"
  display_name = "Monitoring Function Service Account"
  description  = "Service account for the monitoring cloud function with elevated permissions"
}

resource "google_project_iam_member" "monitoring-function-editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.monitoring-function.email}"
}




resource "google_storage_bucket" "cloud-function-bucket" {
  name          = format("cloud-function-bucket-module3-%s", var.project_id)
  location      = var.region
  force_destroy = true
}

resource "google_storage_bucket_object" "gcs-function-file" {
  name   = "main.zip"
  bucket = google_storage_bucket.cloud-function-bucket.name
  source = data.archive_file.main.output_path
}

resource "google_cloudfunctions2_function" "function" {
  name        = "monitoring-function"
  description = "This is a python function used for Module 3"
  location    = var.region
  build_config {
    runtime     = "python39"
    entry_point = "compute_engine_monitoring"
    source {
      storage_source {
        bucket = google_storage_bucket.cloud-function-bucket.name
        object = google_storage_bucket_object.gcs-function-file.name

      }
    }
  }
  service_config {
    max_instance_count    = 200
    service_account_email = google_service_account.monitoring-function.email
  }
}

# IAM entry for all users to invoke the function
# setting the invoker via google_cloudfunctions2_functions_iam_member is not supported yet
resource "google_cloud_run_service_iam_member" "invoker" {
  project  = google_cloudfunctions2_function.function.project
  location = google_cloudfunctions2_function.function.location
  service  = google_cloudfunctions2_function.function.name
  role     = "roles/run.invoker"
  member   = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}

resource "google_project_iam_member" "compute-account-run-viewer" {
  project = var.project_id
  role    = "roles/run.viewer"
  member  = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}

resource "google_project_iam_member" "compute-account-log-writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}


resource "google_project_iam_member" "compute-account-log-viewer" {
  project = var.project_id
  role    = "roles/logging.privateLogViewer"
  member  = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}

resource "google_project_iam_member" "compute-account-cloudfunc-developer"  {
  project = var.project_id
  role    = "roles/cloudfunctions.developer"
  member  = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}

# Allow the project's default Compute Engine SA to read the Cloud Functions v2 staging bucket
resource "google_storage_bucket_iam_member" "compute-account-gcf-v2-sources-object-viewer" {
  bucket = format("gcf-v2-sources-%s-%s", var.project_number, var.region)
  role   = "roles/storage.objectViewer"
  member = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
}

resource "google_artifact_registry_repository_iam_member" "compute-engine-writer-gcf-artifacts" {
  project    = var.project_id
  location   = var.region
  repository = "gcf-artifacts"
  role       = "roles/artifactregistry.writer"
  member  = format("serviceAccount:%s", data.google_service_account.compute-account-module3.email)
  }
