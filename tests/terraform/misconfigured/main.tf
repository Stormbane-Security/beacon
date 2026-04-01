terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Misconfiguration: Public S3 bucket with no encryption
resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Misconfiguration: Open security group allowing all inbound traffic
resource "aws_security_group" "open_sg" {
  name        = "wide-open-sg"
  description = "Intentionally insecure security group"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all inbound TCP"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Misconfiguration: Unencrypted RDS with public access
resource "aws_db_instance" "public_rds" {
  identifier     = "insecure-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = false

  username = "admin"
  password = "SuperSecret123!"

  publicly_accessible    = true
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.open_sg.id]

  backup_retention_period = 0
}

# Misconfiguration: CloudFront allowing HTTP
resource "aws_cloudfront_distribution" "insecure_cdn" {
  enabled = true

  origin {
    domain_name = "example.com"
    origin_id   = "insecure-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "insecure-origin"

    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Misconfiguration: IAM policy with wildcard permissions
resource "aws_iam_policy" "admin_policy" {
  name        = "overly-permissive-policy"
  description = "Policy with wildcard permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Misconfiguration: EC2 instance with IMDSv1 enabled
resource "aws_instance" "insecure_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.open_sg.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # IMDSv1 enabled
  }

  # Unencrypted root volume
  root_block_device {
    volume_size = 20
    encrypted   = false
  }
}

# Misconfiguration: Unencrypted EBS volume
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}
