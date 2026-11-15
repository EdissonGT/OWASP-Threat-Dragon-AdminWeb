# DELIBERATELY insecure infrastructure. Do not apply.
resource "aws_s3_bucket" "data" {
  bucket = "practice-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  storage_encrypted   = false
  publicly_accessible = true
}
