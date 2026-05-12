## Terrible config — fails most security checks

resource "aws_s3_bucket" "public_dump" {
  bucket = "company-public-dump"
  acl    = "public-read"  # (S3-001) CRITICAL: Public bucket!

  # Missing encryption (S3-002)
}

resource "aws_s3_bucket" "backup_bucket" {
  bucket = "internal-backups"
  acl    = "public-read-write"  # (S3-001) CRITICAL: Public read-write!

  # Missing encryption (S3-002)
}

resource "aws_security_group" "yolo_sg" {
  name        = "yolo-access"
  description = "Everything open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # (SG-001) CRITICAL: SSH to world
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # (SG-002) HIGH: All ports open
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # (SG-002) HIGH: RDP open to world
  }
}

resource "aws_instance" "unprotected_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"

  # No metadata_options — IMDSv1 accessible (EC2-001)
}

resource "aws_iam_policy" "god_mode" {
  name = "admin-everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "exposed_db" {
  identifier         = "exposed-database"
  engine             = "postgres"
  instance_class     = "db.t3.medium"
  publicly_accessible = true   # (RDS-001) CRITICAL: Public database!
  storage_encrypted   = false  # (RDS-002) HIGH: No encryption
}

# No CloudTrail at all (LOG-001)

resource "aws_ebs_volume" "raw_vol" {
  availability_zone = "us-east-1a"
  size              = 500
  encrypted         = false  # (EBS-001) MEDIUM: Unencrypted volume
}
