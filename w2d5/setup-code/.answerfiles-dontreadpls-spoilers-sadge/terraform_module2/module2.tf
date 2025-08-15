data "google_service_account" "compute-account-module2" {
  account_id = format("%s-compute@developer.gserviceaccount.com", var.project_number)
}

resource "google_compute_instance" "compute-instance-module2" {
  name         = "app-prod-instance-module2"
  machine_type = "e2-medium"
  zone         = format("%s-%s", var.region, var.zone)

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata = {
    ssh-keys = format("alice:%s", file("../temporary_files/leaked_ssh_key.pub"))
  }

  metadata_startup_script = format("echo PROJECT_ID=%s >> /etc/environment; echo LOCATION=%s >> /etc/environment; echo unset HISTFILE >>/home/alice/.bashrc", var.project_id, var.region)

  service_account {
    email = data.google_service_account.compute-account-module2.email
    # these are the default scopes when creating a compute engine with the compute service account from the cloud console.
    scopes = [
      "https://www.googleapis.com/auth/trace.append",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/devstorage.read_only"
    ]
  }
}

resource "google_secret_manager_secret" "ssh-secret-module2" {
  secret_id = "ssh-key"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "ssh-secret-version-module2" {
  secret = google_secret_manager_secret.ssh-secret-module2.id

  secret_data = filebase64("../temporary_files/leaked_ssh_key")
}

resource "google_storage_bucket" "bucket-module2" {
  name          = format("file-uploads-%s", var.project_id)
  location      = var.region
  force_destroy = true

  public_access_prevention = "enforced"
}

# Grant bucket-service-account read access to the file-uploads bucket for validation scripts
resource "google_storage_bucket_iam_member" "bucket_module2_viewer" {
  bucket = google_storage_bucket.bucket-module2.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:bucket-service-account@${var.project_id}.iam.gserviceaccount.com"
}
