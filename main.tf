provider "aws" {
  region                  = "us-east-1"
  access_key              = "AKIAEXAMPLE"
  secret_key              = "EXAMPLEKEY"
  skip_credentials_validation = true
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "insecure-test-bucket"
  acl    = "public-read"

  versioning {
    enabled = false
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = ""
    target_prefix = "logs/"
  }

  lifecycle_rule {
    enabled = false
  }
}

resource "aws_security_group" "open_sg" {
  name   = "open_sg"
  vpc_id = "vpc-123abc"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "insecure_instance" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  key_name                    = "test_key"
  vpc_security_group_ids      = [aws_security_group.open_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
              systemctl restart sshd
              EOF

  root_block_device {
    volume_size = 8
    encrypted   = false
  }

  tags = {
    Name = "InsecureEC2"
  }
}

resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "aws_db_instance" "insecure_rds" {
  identifier              = "insecure-db"
  instance_class          = "db.t2.micro"
  allocated_storage       = 20
  engine                  = "mysql"
  engine_version          = "5.7"
  username                = "admin"
  password                = "examplepassword"
  publicly_accessible     = true
  skip_final_snapshot     = true
  backup_retention_period = 0
  storage_encrypted       = false
  multi_az                = false
  deletion_protection     = false
}
