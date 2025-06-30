###############################################################################
# ■ 1. ネットワーク & EKS
###############################################################################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.4.0"

  name               = "moop-vpc"
  cidr               = var.vpc_cidr
  azs                = ["${var.aws_region}a", "${var.aws_region}c"]
  public_subnets     = ["10.1.1.0/24", "10.1.2.0/24"]
  private_subnets    = ["10.1.11.0/24", "10.1.12.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = true
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.8.3"

  cluster_name                   = var.cluster_name
  cluster_version                = "1.29"
  cluster_endpoint_public_access = true
  subnet_ids                     = module.vpc.private_subnets
  vpc_id                         = module.vpc.vpc_id

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3a.large"]
      min_size       = 1
      max_size       = 1
      desired_size   = 1
    }
  }
}

###############################################################################
# ■ 2. Redis Serverless (ユーザー必須)
###############################################################################
resource "random_password" "redis_acl_pwd" {
  length  = 32
  special = true
}

resource "aws_elasticache_user" "redis_user" {
  user_id       = "app-user"
  user_name     = "appUser"
  engine        = "REDIS"
  passwords     = [random_password.redis_acl_pwd.result]
  access_string = "on ~* &* +@all"
}

resource "aws_elasticache_user_group" "redis_group" {
  user_group_id = "app-group"
  engine        = "REDIS"
  user_ids      = [aws_elasticache_user.redis_user.user_id, "default"]
}

resource "aws_security_group" "redis" {
  name   = "redis-sg"
  vpc_id = module.vpc.vpc_id

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
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }
}

resource "aws_elasticache_serverless_cache" "redis" {
  name                 = "serverless-redis"
  engine               = "redis"
  major_engine_version = "7"
  subnet_ids           = module.vpc.private_subnets
  security_group_ids   = [aws_security_group.redis.id]
  user_group_id        = aws_elasticache_user_group.redis_group.user_group_id
}

###############################################################################
# ■ 3. Secrets Manager (Redis & RDS)
###############################################################################
# 3-A : Redis
resource "aws_secretsmanager_secret" "redis_secret" {
  name = "redis-token"
}

resource "aws_secretsmanager_secret_version" "redis_secret_version" {
  secret_id = aws_secretsmanager_secret.redis_secret.id
  secret_string = jsonencode({
    host     = aws_elasticache_serverless_cache.redis.endpoint[0].address
    port     = 6379
    username = aws_elasticache_user.redis_user.user_name
    password = random_password.redis_acl_pwd.result
    ssl      = true
  })
}

# 3-B : Oracle RDS
resource "aws_db_subnet_group" "oracle" {
  name       = "oracle-db-subnet-group"
  subnet_ids = module.vpc.private_subnets
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
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }
}

resource "aws_db_instance" "oracle" {
  identifier            = "oracle-db"
  engine                = "oracle-se2-cdb"
  engine_version        = "21.0.0.0.ru-2025-04.rur-2025-04.r1"
  instance_class        = "db.t3.small"
  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  license_model         = "license-included"

  username                    = "admin"
  manage_master_user_password = true

  db_name                = "ORCL"
  port                   = 1521
  db_subnet_group_name   = aws_db_subnet_group.oracle.name
  vpc_security_group_ids = [aws_security_group.rds_oracle.id]

  skip_final_snapshot     = true
  publicly_accessible     = false
  deletion_protection     = false
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}

data "aws_secretsmanager_secret_version" "rds" {
  secret_id = aws_db_instance.oracle.master_user_secret[0].secret_arn
}

resource "aws_secretsmanager_secret" "rds_secret" {
  name = "rds_connection_details"
}

resource "aws_secretsmanager_secret_version" "db_connection_details" {
  secret_id = aws_secretsmanager_secret.rds_secret.id

  secret_string = jsonencode(
    merge(
      jsondecode(data.aws_secretsmanager_secret_version.rds.secret_string),
      {
        "host"                 = aws_db_instance.oracle.address
        "port"                 = aws_db_instance.oracle.port
        "dbname"               = aws_db_instance.oracle.db_name
        "dbInstanceIdentifier" = aws_db_instance.oracle.identifier
      }
    )
  )

  depends_on = [
    aws_db_instance.oracle
  ]
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name = "jwt-secret"
}
resource "aws_secretsmanager_secret_version" "jwt_secret_version" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = jsonencode({ secret = "this_is_a_very_long_random_secret_key_32byte!" })
}
###############################################################################
# ■ 4. ECR
###############################################################################
resource "aws_ecr_repository" "frontend" { name = "react-nginx" }
resource "aws_ecr_repository" "backend" { name = "springboot-api" }

###############################################################################
# ■ 5. IAM for AWS Load Balancer Controller
###############################################################################
data "aws_eks_cluster" "eks" { name = module.eks.cluster_name }
data "aws_partition" "cur" {}

resource "aws_iam_role_policy_attachment" "alb_managed" {
  role       = module.iam_eks_alb_controller.iam_role_name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

module "iam_eks_alb_controller" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.38.0"

  create_role                   = true
  role_name                     = "${var.cluster_name}-alb-controller"
  provider_url                  = replace(data.aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://", "")
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
}

resource "kubernetes_service_account" "alb_controller" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.iam_eks_alb_controller.iam_role_arn
    }
    labels = { "app.kubernetes.io/name" = "aws-load-balancer-controller" }
  }
}

###############################################################################
# ■ 6. Helm Provider & Releases (Argo CD / ALB Controller / ESO)
###############################################################################
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

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

# Argo CD
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

# ALB Controller
resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "./eks-charts/stable"
  chart      = "aws-load-balancer-controller"
  version    = "1.8.1"

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = kubernetes_service_account.alb_controller.metadata[0].name
  }
  set {
    name  = "region"
    value = var.aws_region
  }
  set {
    name  = "vpcId"
    value = module.vpc.vpc_id
  }
  depends_on = [kubernetes_service_account.alb_controller, aws_iam_role_policy_attachment.alb_managed]
}

###############################################################################
# ■ 7. Bastion（踏み台）サーバ & SSM
###############################################################################

# Bastionサーバ用のセキュリティグループ（RDSに接続できるように）
resource "aws_security_group" "bastion" {
  name   = "bastion-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 1521
    to_port         = 1521
    protocol        = "tcp"
    security_groups = [aws_security_group.rds_oracle.id]
    description     = "Allow Oracle RDS connection"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SSM用のIAMロール
resource "aws_iam_role" "bastion" {
  name = "bastion-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Bastion用のEC2インスタンス
resource "aws_instance" "bastion" {
  ami                    = data.aws_ami.amazon_linux.id # 後述
  instance_type          = "t3.micro"
  subnet_id              = module.vpc.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.bastion.id]
  iam_instance_profile   = aws_iam_instance_profile.bastion.name

  tags = {
    Name = "bastion"
  }
}

# EC2にIAMロールを紐付け
resource "aws_iam_instance_profile" "bastion" {
  name = "bastion-ssm-profile"
  role = aws_iam_role.bastion.name
}

# Amazon Linux2のAMI取得
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


########################
# 0. ESO共通ローカル値
########################
locals {
  eso_namespace = "external-secrets"
  sa_name       = "external-secrets-operator"
  role_name     = "eks-external-secrets-operator"
}

########################
# 1. Namespace
########################
resource "kubernetes_namespace" "eso" {
  metadata {
    name = local.eso_namespace
  }
}

########################
# 2. IAM for IRSA
########################
data "aws_iam_policy_document" "assume_oidc" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(data.aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:${local.eso_namespace}:${local.sa_name}"]
    }
  }
}

resource "aws_iam_role" "eso" {
  name               = local.role_name
  assume_role_policy = data.aws_iam_policy_document.assume_oidc.json
}

resource "aws_iam_role_policy_attachment" "secrets_manager_read_write" {
  role       = aws_iam_role.eso.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

########################
# 3. ServiceAccount
########################
resource "kubernetes_service_account" "eso" {
  metadata {
    name      = local.sa_name
    namespace = local.eso_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.eso.arn
    }
  }
}

########################
# 4. Helm Release (ESO)
########################
resource "helm_release" "external_secrets" {
  name  = "external-secrets"
  chart = "./charts/external-secrets"
  # repository = "https://charts.external-secrets.io"
  namespace = local.eso_namespace
  version   = "0.9.20"

  # cert-manager 無しの環境向け：Webhook TLS を自己署名
  set {
    name  = "webhook.certs.selfSigned.enabled"
    value = "true"
  }

  # 既に SA を自分で作ったので Helm 側で作らない
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = local.sa_name
  }

  depends_on = [kubernetes_service_account.eso]
}
