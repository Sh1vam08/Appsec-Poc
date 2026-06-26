# BENCH-IAC-024: GCP Storage Bucket publicly accessible
# Tests: Infrastructure configuration analysis, Resource exposure analysis

resource "google_storage_bucket" "vulnerable_bucket" {
  name          = "vulnerable-public-gcp-bucket"
  location      = "US"
  force_destroy = true

  # No uniform bucket-level access — uses legacy ACLs
  uniform_bucket_level_access = false
}

# Make the bucket publicly readable
resource "google_storage_bucket_iam_member" "public_access" {
  bucket = google_storage_bucket.vulnerable_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# BENCH-IAC-025: GCP Compute Instance with public IP and no OS Login
# Tests: Identity and access configuration, Misconfiguration detection

resource "google_compute_instance" "vulnerable_instance" {
  name         = "vulnerable-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"

    # Public IP assigned — instance is internet-facing
    access_config {}
  }

  # OS Login disabled — uses legacy SSH key management
  metadata = {
    enable-oslogin = "FALSE"
    # Hardcoded SSH key
    ssh-keys = "admin:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt3c6GgK1 admin@example.com"
  }

  # No service account scoping — uses default compute SA with full access
  service_account {
    scopes = ["cloud-platform"]  # Full access to all GCP APIs
  }
}

# BENCH-IAC-026: GCP Firewall allowing all ingress
# Tests: Network configuration analysis (IaC context)

resource "google_compute_firewall" "vulnerable_firewall" {
  name    = "allow-all-ingress"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}
