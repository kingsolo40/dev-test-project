# Creating a VPC for a project

resource "aws_vpc" "prod-rock-vpc" {
  cidr_block           = var.vpc-cidr
  instance_tenancy     = "default"
  enable_dns_hostnames = true

  tags = {
    Name = "prod-rock-vpc"
  }
}

# Creating two public subnets for the aws_vpc

resource "aws_subnet" "test-pub-sub1" {
  vpc_id            = aws_vpc.prod-rock-vpc.id
  cidr_block        = var.public-cidr1
  availability_zone = var.availability-z-1
  tags = {
    Name = "test-pub-sub1"
  }
}

resource "aws_subnet" "test-pub-sub2" {
  vpc_id            = aws_vpc.prod-rock-vpc.id
  cidr_block        = var.public-cidr2
  availability_zone = var.availability-z-2

  tags = {
    Name = "test-pub-sub2"
  }
}

# Creating two Private Subnets for the aws_vpc

resource "aws_subnet" "test-priv-sub1" {
  vpc_id            = aws_vpc.prod-rock-vpc.id
  cidr_block        = var.private-cidr1
  availability_zone = var.availability-z-1

  tags = {
    Name = "test-priv-sub1"
  }
}

resource "aws_subnet" "test-priv-sub2" {
  vpc_id            = aws_vpc.prod-rock-vpc.id
  cidr_block        = var.private-cidr2
  availability_zone = var.availability-z-2

  tags = {
    Name = "test-priv-sub2"
  }
}

# Creating two route tables,one public and the other private

resource "aws_route_table" "test-pub-route-table" {
  vpc_id = aws_vpc.prod-rock-vpc.id

  tags = {
    Name = "test-pub-route-table"
  }
}

resource "aws_route_table" "test-priv-route-table" {
  vpc_id = aws_vpc.prod-rock-vpc.id

  tags = {
    Name = "test-priv-route-table"
  }
}

# Associating subnets to the routes respectively

resource "aws_route_table_association" "public-association1" {
  subnet_id      = aws_subnet.test-pub-sub1.id
  route_table_id = aws_route_table.test-pub-route-table.id
}

resource "aws_route_table_association" "private-association1" {
  subnet_id      = aws_subnet.test-priv-sub1.id
  route_table_id = aws_route_table.test-priv-route-table.id
}

# Creating an internet gateway

resource "aws_internet_gateway" "test-igw" {
  vpc_id = aws_vpc.prod-rock-vpc.id

  tags = {
    Name = "test-igw"
  }
}

# creating elastic ip gateway

resource "aws_eip" "prod-elastic-ip" {
  vpc = true

  tags = {
    Name = "prod-elastic-ip"
  }
}

# creating nat gateway
resource "aws_nat_gateway" "test-nat-gateway" {
  allocation_id     = aws_eip.prod-elastic-ip.id
  subnet_id         = aws_subnet.test-pub-sub1.id
  connectivity_type = "public"

  tags = {
    Name = "test-nat-gateway"
  }
  depends_on = [aws_internet_gateway.test-igw]
}

# creating association nat gateway with private subnet 

resource "aws_route" "elatic-ip-association" {
  route_table_id         = aws_route_table.test-priv-route-table.id
  gateway_id             = aws_internet_gateway.test-igw.id
  destination_cidr_block = "0.0.0.0/0"
}

# creating security group

resource "aws_security_group" "test-sec-group" {
  name        = "test-sec-group"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.prod-rock-vpc.id

  ingress {
    description = "security group with ingresss http port opened"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "security group with ingress http port opened"
    from_port   = 22
    to_port     = 22
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
    Name = "allow_tls"
  }
}

# creating a servers for eu-west-2

resource "aws_instance" "test-server1" {
  ami                    = "ami-0758d98b134137d18"
  key_name               = "key-pem-server1"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.test-pub-sub1.id
  vpc_security_group_ids = [aws_security_group.test-sec-group.id]
  }

resource "aws_instance" "test-server2" {
  ami                    = "ami-0758d98b134137d18"
  key_name               = "key-pem-server1"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.test-priv-sub1.id
  vpc_security_group_ids = [aws_security_group.test-sec-group.id]
  availability_zone = var.availability-z-1
  tags ={
  name = "test-server2"
    }
}
# creating aws iam role

resource "aws_iam_role" "prod-dev-role" {
  name = "prod-dev-role"
  assume_role_policy = jsonencode ({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# creating aws iam policy
resource "aws_iam_policy" "policy" {
  name        = "prod.dev.policy"
  path        = "/"
  description = "My test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

# attching policy to the role

data "aws_iam_policy" "user-policy" {
  arn = "arn:aws:iam::208159010078:policy/user-policy"
}
resource "aws_iam_role_policy_attachment" "aws_iam_policy-user-policy-attach" {
  role       = "${aws_iam_role.prod-dev-role.name}"
  policy_arn = data.aws_iam_policy.user-policy.arn
}


