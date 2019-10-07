## wkandek test enviromnent TF in AWS
# sets up 2 servers in 2 subnets
# server 1 has nginx
# server 2 has nginx
# a loadbalancers balnces between the 2
# V3.2
# - add install s3cmd
# V3.3
# - add S3 and copy of logs to it
# V3.4
# - tags
# - add redis and python app.py
# - restart app.py via supervisor

## Variables
variable "aws_access_key" {
  description = "abc"
}
variable "aws_secret_key" {
  description = "def"
}
variable "private_key_path" {
  description = "ghi"
}

variable "network_address_space" {
  default = "10.1.0.0/16"
}
variable "subnet1_address_space" {
  default = "10.1.0.0/24"
}
variable "subnet2_address_space" {
  default = "10.1.1.0/24"
}
variable "subnet3_address_space" {
  default = "10.1.2.0/24"
}

variable "billing_code_tag" {}
variable "environment_tag" {}
variable "bucket_name" {}

## Local vars
locals {
  common_tags = {
    BillingCode = var.billing_code_tag
    Environment = var.environment_tag
  }
}

## Provider
provider "aws" {
  region = "us-east-2"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
}

data "aws_availability_zones" "available" {
  state = "available"
}


## Networks
resource "aws_vpc" "vpc" {
  cidr_block = "${var.network_address_space}"
  enable_dns_hostnames = "true"
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-vpc" })
}
resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.vpc.id}"
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-igw" })
}
resource "aws_subnet" "subnet1" {
  cidr_block = "${var.subnet1_address_space}"
  vpc_id = "${aws_vpc.vpc.id}"
  map_public_ip_on_launch = "true"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-subnet1" })
}
resource "aws_subnet" "subnet2" {
  cidr_block = "${var.subnet2_address_space}"
  vpc_id = "${aws_vpc.vpc.id}"
  map_public_ip_on_launch = "true"
  availability_zone = "${data.aws_availability_zones.available.names[1]}"
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-subnet2" })
}
resource "aws_subnet" "subnet3" {
  cidr_block = "${var.subnet3_address_space}"
  vpc_id = "${aws_vpc.vpc.id}"
  map_public_ip_on_launch = "true"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-subnet3" })
}

resource "aws_route_table" "rtb" {
  vpc_id = "${aws_vpc.vpc.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.igw.id}"
  }
}
resource "aws_route_table_association" "rta-subnet1" {
  subnet_id = "${aws_subnet.subnet1.id}"
  route_table_id = "${aws_route_table.rtb.id}"
}
resource "aws_route_table_association" "rta-subnet2" {
  subnet_id = "${aws_subnet.subnet2.id}"
  route_table_id = "${aws_route_table.rtb.id}"
}
resource "aws_route_table_association" "rta-subnet3" {
  subnet_id = "${aws_subnet.subnet3.id}"
  route_table_id = "${aws_route_table.rtb.id}"
}


## Security Groups
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    # TLS (change to whatever ports you need)
    from_port   = 22 
    to_port     = 22 
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # add a CIDR block here
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP inbound traffic"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    # TLS (change to whatever ports you need)
    from_port   = 80 
    to_port     = 80 
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # add a CIDR block here
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    # TLS (change to whatever ports you need)
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # add a CIDR block here
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_althttp" {
  name        = "allow_althttp"
  description = "Allow HTTP on 5000 inbound traffic"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    # TLS (change to whatever ports you need)
    from_port   = 5000 
    to_port     = 5000 
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # add a CIDR block here
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_redis" {
  name        = "allow_redis"
  description = "Allow 6379 inbound traffic"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    # TLS (change to whatever ports you need)
    from_port   = 6379 
    to_port     = 6379 
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # add a CIDR block here
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

## LBs
resource "aws_elb" "web" {
  name = "nginx-elb"
  subnets = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  security_groups = [aws_security_group.allow_http.id]
  instances = [aws_instance.nginx1.id,aws_instance.nginx2.id]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}


# VMs
resource "aws_instance" "nginx1" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = "${aws_subnet.subnet1.id}"
  key_name = "start"
  vpc_security_group_ids = ["${aws_security_group.allow_ssh.id}",
                            "${aws_security_group.allow_http.id}",
                            "${aws_security_group.allow_althttp.id}"]

  connection {
    type = "ssh"
    host = self.public_ip
    user = "ubuntu"
    private_key = "${file("~/.ssh/start.pem")}"
  }

  provisioner "file" { 
    content = <<EOF
server {
    listen 80;
    location / {
        proxy_pass          http://127.0.0.1:5000;
    }
}
EOF
    destination = "/home/ubuntu/default"
  }
  provisioner "file" { 
    content = <<EOF
nginx1
EOF
    destination = "/home/ubuntu/index.html"
  }
  provisioner "file" { 
    content = <<EOF
[program:app]
command=python3 /home/ubuntu/app.py
EOF
    destination = "/home/ubuntu/apppy.conf"
  }
  provisioner "file" { 
    source = "app.py"
    destination = "/home/ubuntu/app.py"
  }
  provisioner "file" { 
    source = "base.html"
    destination = "/home/ubuntu/base.html"
  }
  provisioner "file" { 
    content = <<EOF
${aws_instance.redis.private_ip} redis
EOF
    destination = "/home/ubuntu/hosts"
  }
  provisioner "file" { 
    content = <<EOF
access_key = ${aws_iam_access_key.write_user.id}
secret_key = ${aws_iam_access_key.write_user.secret}
use_https = True
bucket_location = US

EOF
    destination = "/home/ubuntu/.s3cfg"
  }
  provisioner "file" { 
    content = <<EOF
/var/log/nginx/*log {
  daily
  rotate 10
  missingok
  compress
  postrotate
    INSTANCE_ID=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`
    /usr/bin/s3cmd sync /var/log/nginx/access.log.* s3://${aws_s3_bucket.web_bucket.id}/$INSTANCE_ID/weblogs/
  endscript

EOF
    destination = "/home/ubuntu/nginx"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "sudo apt-get -y install nginx", 
      "sudo apt-get update",
      "echo POINT1 && sleep 60",
      "sudo apt-get -y install s3cmd",
      "sudo apt-get -y install supervisor",
      "sudo apt-get -y install python3-flask",
      "sudo apt-get -y install python3-redis",
      "sudo cp /home/ubuntu/.s3cfg /root/.s3cfg",
      "sudo cp /home/ubuntu/nginx /etc/logrotate.d/nginx",
      "sudo cp /home/ubuntu/index.html /var/www/html",
      "sudo cp /home/ubuntu/apppy.conf /etc/supervisor/conf.d",
      "sudo cp /home/ubuntu/default /etc/nginx/sites-available",
      "sudo mkdir /home/ubuntu/templates",
      "sudo mv /home/ubuntu/base.html /home/ubuntu/templates/",
      "echo 'cat /home/ubuntu/hosts >> /etc/hosts' | sudo -s",
      "sudo systemctl enable nginx",
      "sudo logrotate -f /etc/logrotate.conf",
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "echo '/sbin/shutdown -r now' | sudo /usr/bin/at now + 10 minutes"
    ]
  }
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-nginx1" })
}

resource "aws_instance" "nginx2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = "${aws_subnet.subnet2.id}"
  key_name = "start"
  vpc_security_group_ids = ["${aws_security_group.allow_ssh.id}",
                            "${aws_security_group.allow_http.id}",
                            "${aws_security_group.allow_althttp.id}"]

  connection {
    type = "ssh"
    host = self.public_ip
    user = "ubuntu"
    private_key = "${file("~/.ssh/start.pem")}"
  }

  provisioner "file" { 
    content = <<EOF
server {
    listen 80;
    location / {
        proxy_pass          http://127.0.0.1:5000;
    }
}
EOF
    destination = "/home/ubuntu/default"
  }
  provisioner "file" { 
    content = <<EOF
nginx2
EOF
    destination = "/home/ubuntu/index.html"
  }
  provisioner "file" { 
    content = <<EOF
[program:app]
command=python3 /home/ubuntu/app.py
EOF
    destination = "/home/ubuntu/apppy.conf"
  }
  provisioner "file" { 
    source = "app.py"
    destination = "/home/ubuntu/app.py"
  }
  provisioner "file" { 
    source = "base.html"
    destination = "/home/ubuntu/base.html"
  }
  provisioner "file" { 
    content = <<EOF
${aws_instance.redis.private_ip} redis
EOF
    destination = "/home/ubuntu/hosts"
  }
  provisioner "file" { 
    content = <<EOF
access_key = ${aws_iam_access_key.write_user.id}
secret_key = ${aws_iam_access_key.write_user.secret}
use_https = True
bucket_location = US

EOF
    destination = "/home/ubuntu/.s3cfg"
  }
  provisioner "file" { 
    content = <<EOF
/var/log/nginx/*log {
  daily
  rotate 10
  missingok
  compress
  sharedscripts
  postrotate
    INSTANCE_ID=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`
    /usr/bin/s3cmd sync /var/log/nginx/access.log.* s3://${aws_s3_bucket.web_bucket.id}/$INSTANCE_ID/weblogs/
  endscript


EOF
    destination = "/home/ubuntu/nginx"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "sudo apt-get -y install nginx", 
      "sudo apt-get update",
      "echo POINT1 && sleep 60",
      "sudo apt-get -y install s3cmd",
      "sudo apt-get -y install supervisor",
      "sudo apt-get -y install python3-flask",
      "sudo apt-get -y install python3-redis",
      "sudo cp /home/ubuntu/.s3cfg /root/.s3cfg",
      "sudo cp /home/ubuntu/nginx /etc/logrotate.d/nginx",
      "sudo cp /home/ubuntu/index.html /var/www/html",
      "sudo cp /home/ubuntu/apppy.conf /etc/supervisor/conf.d",
      "sudo cp /home/ubuntu/default /etc/nginx/sites-available",
      "sudo mkdir /home/ubuntu/templates",
      "sudo mv /home/ubuntu/base.html /home/ubuntu/templates/",
      "echo 'cat /home/ubuntu/hosts >> /etc/hosts' | sudo -s",
      "sudo systemctl enable nginx",
      "sudo logrotate -f /etc/logrotate.conf",
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "echo '/sbin/shutdown -r now' | sudo /usr/bin/at now + 10 minutes"
    ]
  }
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-nginx2" })
}

resource "aws_instance" "redis" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = "${aws_subnet.subnet3.id}"
  key_name = "start"
  vpc_security_group_ids = ["${aws_security_group.allow_ssh.id}",
                            "${aws_security_group.allow_redis.id}"]

  connection {
    type = "ssh"
    host = self.public_ip
    user = "ubuntu"
    private_key = "${file("~/.ssh/start.pem")}"
  }

  provisioner "file" { 
    content = <<EOF
protected-mode no
bind 0.0.0.0
EOF
    destination = "/home/ubuntu/redis"
  }
  provisioner "file" { 
    content = <<EOF
access_key = ${aws_iam_access_key.write_user.id}
secret_key = ${aws_iam_access_key.write_user.secret}
use_https = True
bucket_location = US

EOF
    destination = "/home/ubuntu/.s3cfg"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "sudo apt-get update",
      "echo POINT1 && sleep 60",
      "sudo apt-get -y install redis", 
      "sudo apt-get -y install s3cmd",
      "sudo cp /home/ubuntu/.s3cfg /root/.s3cfg",
      "sudo cat /home/ubuntu/hosts >> /etc/hosts",
      "sudo logrotate -f /etc/logrotate.conf",
      "sudo systemctl enable redis",
      "echo 'cat /home/ubuntu/redis >> /etc/redis/redis.conf' | sudo -s",
      "sudo apt-get update",
      "sudo apt-get -y upgrade",
      "echo '/sbin/shutdown -r now' | sudo /usr/bin/at now + 10 minutes"
    ]
  }
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-redis" })
}


## Buckets
resource "aws_iam_user" "write_user" {
  name = "${var.environment_tag}-s3-write-user"
}
resource "aws_iam_access_key" "write_user" {
  user = "${aws_iam_user.write_user.name}"
}

resource "aws_iam_user_policy" "write_user_pol" {
  name = "write"
  user = "${aws_iam_user.write_user.name}"
  policy = <<EOF
{
  "Version":"2012-10-17",
  "Statement": [
     {
      "Effect":"Allow",
      "Action":"s3:*",
      "Resource": [
        "arn:aws:s3:::${var.environment_tag}-${var.bucket_name}",
        "arn:aws:s3:::${var.environment_tag}-${var.bucket_name}/*"
      ]
     }
   ]
}

EOF
}

resource "aws_s3_bucket" "web_bucket" {
  bucket = "${var.environment_tag}-${var.bucket_name}"
  acl = "private"
  force_destroy = true
  tags = merge(local.common_tags, { Name = "${var.environment_tag}-web_bucket" })

  policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "PublicReadForGetBucketObjects",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${var.environment_tag}-${var.bucket_name}/*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_user.write_user.arn}"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::${var.environment_tag}-${var.bucket_name}/*"
    }
  ]
}

EOF
}


output "aws_instance_public_dns" {
  value = "${aws_elb.web.dns_name}"
}
