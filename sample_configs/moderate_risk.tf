## Moderate risk config — some findings (score ~30-50)

resource "aws_s3_bucket" "app_bucket" {
  bucket = "my-app-data"
  acl    = "private"

  # Missing encryption (S3-002)
}

resource "aws_security_group" "web_sg" {
  name        = "web-access"
  description = "Web server access"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # (SG-002) HIGH: HTTP open to world
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # (SG-002) HIGH: HTTPS open to world
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"

  # No metadata_options — IMDSv1 accessible (EC2-001)
}

resource "aws_db_instance" "app_db" {
  identifier          = "app-database"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_cloudtrail" "app_trail" {
  name           = "app-audit-trail"
  s3_bucket_name = "my-app-data"
}

resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 200
  encrypted         = false  # (EBS-001) MEDIUM: Unencrypted
}
