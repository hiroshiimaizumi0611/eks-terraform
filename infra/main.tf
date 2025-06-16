module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.4.0"
  name    = "moop-vpc"
  cidr    = var.vpc_cidr
  azs     = ["${var.aws_region}a", "${var.aws_region}c"]
  public_subnets  = ["10.1.1.0/24", "10.1.2.0/24"]
  private_subnets = ["10.1.11.0/24", "10.1.12.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = true
}

module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "20.8.3"
  cluster_name    = var.cluster_name
  cluster_version = "1.29"
  subnet_ids      = module.vpc.private_subnets
  vpc_id          = module.vpc.vpc_id
  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    default = {
      instance_types = ["m6i.large"]
      min_size       = 1
      max_size       = 1
      desired_size   = 1
    }
  }
}

resource "aws_security_group" "redis" {
  name        = "redis-sg"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_serverless_cache" "redis" {
  name                   = "serverless-redis"
  engine                 = "redis"
  major_engine_version   = "7"
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [aws_security_group.redis.id]
}

resource "aws_ecr_repository" "frontend" { name = "react-nginx"}

resource "aws_ecr_repository" "backend" { name = "springboot-api"}

resource "aws_db_subnet_group" "oracle" {
  name        = "oracle-db-subnet-group"
  subnet_ids  = module.vpc.private_subnets
  description = "Subnet group for RDS Oracle"
}

resource "aws_security_group" "rds_oracle" {
  name        = "rds-oracle-sg"
  description = "Security group for RDS Oracle"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 1521
    to_port     = 1521
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "oracle" {
  identifier             = "oracle-db"
  engine                 = "oracle-se2-cdb"
  engine_version         = "21.0.0.0.ru-2025-04.rur-2025-04.r1"
  instance_class         = "db.m5.large"
  allocated_storage      = 100
  max_allocated_storage  = 500
  storage_type           = "gp3"
  storage_encrypted      = true
  multi_az               = false
  license_model         = "license-included"

  username               = "admin"
  password               = var.oracle_db_password

  db_name                = "ORCL"
  port                   = 1521

  db_subnet_group_name   = aws_db_subnet_group.oracle.name
  vpc_security_group_ids = [aws_security_group.rds_oracle.id]

  skip_final_snapshot    = true
  publicly_accessible    = false
  deletion_protection    = false

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}

data "aws_eks_cluster" "eks" {
   name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  # EKS 用トークンを自動取得
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}
   
module "iam_eks_alb_controller" { 
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc" 
  version = "5.38.0" 
  create_role = true 
  role_name = "${var.cluster_name}-alb-controller" 
  provider_url = replace(data.aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://", "") 
  role_policy_arns = ["arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy"] 
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
}
    
resource "kubernetes_service_account" "alb_controller" { 
  metadata { 
    name = "aws-load-balancer-controller" 
    namespace = "kube-system" 
    labels = { "app.kubernetes.io/name" = "aws-load-balancer-controller" } 
    annotations = { "eks.amazonaws.com/role-arn" = module.iam_eks_alb_controller.iam_role_arn }
  }
}


# # Helm provider設定（EKS情報流用）
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = "argocd"
  chart            = "argo-cd"
  repository       = "./"
  version          = "5.46.4"
  create_namespace = true

  set {
    name  = "server.service.type"
    value = "LoadBalancer"
  }
}