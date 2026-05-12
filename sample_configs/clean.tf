## Clean config — passes all security checks (score 0)

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "restricted_sg" {
  name        = "restricted-access"
  description = "Only internal traffic"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "hardened_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_db_instance" "private_db" {
  identifier          = "private-database"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_cloudtrail" "main_trail" {
  name                          = "main-audit-trail"
  s3_bucket_name                = "my-secure-bucket"
  include_global_service_events = true
  is_multi_region_trail         = true
}

resource "aws_ebs_volume" "encrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}
