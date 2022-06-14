variable "vpc-cidr" {
  type        = string
  description = "name of vpc-cidr"
  default     = "10.0.0.0/16"
}


variable "public-cidr1" {
  type        = string
  description = "name of public-cidr1"
  default     = "10.0.0.0/24"

}

variable "public-cidr2" {
  type        = string
  description = "name of public-cidr2"
  default     = "10.0.1.0/24"

}

variable "private-cidr1" {
  type        = string
  description = "name of private-cidr3"
  default     = "10.0.2.0/24"

}

variable "private-cidr2" {
  type        = string
  description = "name of private-cidr"
  default     = "10.0.3.0/24"
}

variable "availability-z-1" {
  type        = string
  description = "name of availability zone"
  default     = "eu-west-2a"
}

variable "availability-z-2" {
  type        = string
  description = "name of availability zone"
  default     = "eu-west-2b"
}

variable "availability-z-3" {
  type        = string
  description = "name of availability zone"
  default     = "eu-west-2c"
}

variable "availability-z-4" {
  type        = string
  description = "name of availability zone"
  default     = "eu-west-2a"
}

variable "region-name" {
  type        = string
  description = "name of region"
  default     = "eu-west-2"
}

variable "ubuntu-ami-ec2-instance" {
  type        = string
  description = "ubuntu-ami-ec2-instance"
  default     = "t2.micro"

}

variable "ami-id" {
  type        = string
  description = "ami"
  default     = "ami-0184e674549ab8432"

}
