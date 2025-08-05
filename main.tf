terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Random string for unique resource names
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# VPC and Networking
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cbdc-app-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "cbdc-app-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "cbdc-app-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "cbdc-app-private-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "cbdc-app-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Groups with Intentional Vulnerabilities
resource "aws_security_group" "mongodb_sg" {
  name        = "mongodb-sg"
  description = "Security group for MongoDB instance"
  vpc_id      = aws_vpc.main.id

  # Intentionally vulnerable - SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MongoDB port - intentionally open to world
  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mongodb-sg"
  }
}

resource "aws_security_group" "eks_cluster" {
  name        = "eks-cluster-sg"
  description = "Security group for EKS cluster"
  vpc_id      = aws_vpc.main.id

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

  tags = {
    Name = "eks-cluster-sg"
  }
}

# EKS Cluster
resource "aws_eks_cluster" "main" {
  name     = "cbdc-app-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.27"

  vpc_config {
    subnet_ids         = [aws_subnet.public.id, aws_subnet.private.id]
    security_group_ids = [aws_security_group.eks_cluster.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
  ]

  tags = {
    Name = "cbdc-app-cluster"
  }
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "cbdc-app-nodes"
  node_role_arn   = aws_iam_role.eks_node_group.arn
  subnet_ids      = [aws_subnet.private.id]

  instance_types = ["t3.medium"]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_node_group_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_registry_policy,
  ]

  tags = {
    Name = "cbdc-app-nodes"
  }
}

# IAM Roles for EKS
resource "aws_iam_role" "eks_cluster" {
  name = "cbdc-app-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_node_group" {
  name = "cbdc-app-eks-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node_group_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group.name
}

# S3 Bucket with Intentional Public Access
resource "aws_s3_bucket" "db_backups" {
  bucket = "cbdc-app-db-backups-${random_string.bucket_suffix.result}"

  tags = {
    Name = "cbdc-app-db-backups"
  }
}

resource "aws_s3_bucket_public_access_block" "db_backups" {
  bucket = aws_s3_bucket.db_backups.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "db_backups_policy" {
  bucket = aws_s3_bucket.db_backups.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.db_backups.arn,
          "${aws_s3_bucket.db_backups.arn}/*"
        ]
      }
    ]
  })
}

# Replace the existing aws_key_pair resource with:
resource "aws_key_pair" "mongodb_key" {
  key_name   = "cbdc-app-mongodb-key"
  public_key = var.ssh_public_key
}


# MongoDB EC2 Instance with Vulnerabilities
resource "aws_instance" "mongodb" {
  ami                    = "ami-0c02fb55956c7d316" # Amazon Linux 2 (outdated)
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.mongodb_key.key_name
  vpc_security_group_ids = [aws_security_group.mongodb_sg.id]
  subnet_id              = aws_subnet.public.id
  iam_instance_profile   = aws_iam_instance_profile.mongodb_profile.name

  user_data = base64encode(templatefile("${path.module}/mongodb_userdata.sh", {
    s3_bucket = aws_s3_bucket.db_backups.bucket
  }))

  tags = {
    Name = "cbdc-app-mongodb"
  }
}

# Overly Permissive IAM Role for MongoDB Instance
resource "aws_iam_role" "mongodb_role" {
  name = "cbdc-app-mongodb-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "mongodb_profile" {
  name = "cbdc-app-mongodb-profile"
  role = aws_iam_role.mongodb_role.name
}

# Intentionally overly permissive policy
resource "aws_iam_role_policy" "mongodb_policy" {
  name = "cbdc-app-mongodb-policy"
  role = aws_iam_role.mongodb_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "iam:*",
          "eks:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# ECR Repository
resource "aws_ecr_repository" "cbdc_app" {
  name = "cbdc-app"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "cbdc-app-repo"
  }
}

# Security Hub
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }

  tags = {
    Name = "cbdc-app-guardduty"
  }
}
