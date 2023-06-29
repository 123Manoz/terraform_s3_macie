provider "aws" {
  region = "us-east-1"

  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

resource "random_pet" "this" {
  length = 2
}

data "aws_region" "current" {}

################################################################################
# Lambda Module
################################################################################

################################################################################
# Extra Resources
################################################################################


data "aws_ec2_managed_prefix_list" "this" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}



module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = random_pet.this.id
  cidr = "10.0.0.0/16"

  azs = ["${data.aws_region.current.name}a", "${data.aws_region.current.name}b", "${data.aws_region.current.name}c"]

  # Intra subnets are designed to have no Internet access via NAT Gateway.
  intra_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  intra_dedicated_network_acl = true
  intra_inbound_acl_rules = concat(
    # NACL rule for local traffic
    [
      {
        rule_number = 100
        rule_action = "allow"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_block  = "10.0.0.0/16"
      },
    ],
    # NACL rules for the response traffic from addresses in the AWS S3 prefix list
    [for k, v in zipmap(
      range(length(data.aws_ec2_managed_prefix_list.this.entries[*].cidr)),
      data.aws_ec2_managed_prefix_list.this.entries[*].cidr
      ) :
      {
        rule_number = 200 + k
        rule_action = "allow"
        from_port   = 1024
        to_port     = 65535
        protocol    = "tcp"
        cidr_block  = v
      }
    ]
  )
}


module "vpc_endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "~> 5.0"

  vpc_id = module.vpc.vpc_id

  endpoints = {
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = module.vpc.intra_route_table_ids
      policy          = data.aws_iam_policy_document.endpoint.json
    }
  }
}

data "aws_iam_policy_document" "endpoint" {
  statement {
    sid = "RestrictBucketAccessToIAMRole"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]

    resources = [
      "${module.s3_bucket.s3_bucket_arn}/*",
    ]

    # See https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html#edit-vpc-endpoint-policy-s3
    # condition {
    #   test     = "ArnEquals"
    #   variable = "aws:PrincipalArn"
    #   values   = [module.lambda_s3_write.lambda_role_arn]
    # }
  }
}


data "aws_iam_policy_document" "kms_use" {
  statement {
    sid = "Allow KMS Use"
    effect = "Allow"
    principals {
    type = "AWS"
    identifiers = ["arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [
      "*"
    ]
  }
}


data "aws_iam_policy_document" "bucket" {
  statement {
        sid = "Access from specific VPCE only"
        effect = "Deny"
        principals {
       type = "*"
      identifiers = ["*"]
    }
  
        actions = ["s3:*"]
        resources = ["arn:aws:s3:::*"]
        condition {
          test = "StringNotEquals" 
            variable =  "aws:SourceVpce"
            values= [ "${module.vpc_endpoints.endpoints["s3"]}"
            ]
        }
        condition {
        test = "StringNotLike"
        variable = "aws:PrincipalArn"
        values = [
          "arn:aws:iam::505939268275:role/aws-service-role/macie.use-east-1.amazonaws.com/AWSServiceRoleForAmazonMacie",
          "arn:aws:iam::505939268275:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
        ]
        }
      }
 
   
}

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 1.0"

  description = "S3 encryption key"

  policy = "${data.aws_iam_policy_document.kms_use.json}"
}

  # Grants
  # grants = {
  #   lambda = {
  #     grantee_principal = "arn:aws:iam::505939268275:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
  #     operations = [
  #       "GenerateDataKey",
  #     ]
  #   }
  # }


module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket_prefix = "${random_pet.this.id}-"
  force_destroy = true

  # S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  versioning = {
    enabled = true
  }

  # Bucket policy
  attach_policy = true
  policy        = data.aws_iam_policy_document.bucket.json

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.kms.key_id
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

# data "aws_iam_policy_document" "bucket" {
#   Statement": [
#       {
#         "Sid": "DenyIfNotFromAllowedVPCendpoint",
#         "Effect": "Deny",
#         "Principal": "*",
#         "Action": "s3:*",
#         "Resource": [
#           "arn:aws:s3:::bucket-name-${name_prefix}",
#           "arn:aws:s3:::bucket-name-${name_prefix}/*"
#                     ],
#         "Condition": {
#           "StringNotEquals": {
#             "aws:userid" : "AIDFFKDXKYRYIOPRT1C3E",
#             "aws:sourceVpce": "${vpc_endpoint}"
#           }
#         }
#       }
#     ]
# }

################# macie policies to enable ########################

# macie service role 

data "aws_iam_role" "macieservicerole" {
  name = "AWSServiceRoleForAmazonMacie"
} 

data "aws_caller_identity" "current" {
    
}


locals {
    account_id = data.aws_caller_identity.current.account_id
}



resource "aws_macie2_account" "enabletest_macie" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

resource "aws_macie2_classification_job" "classification_job" {
  job_type = "ONE_TIME"
  name     = "NAME OF THE CLASSIFICATION JOB"
  s3_job_definition {
    bucket_definitions {
      account_id = local.account_id
      buckets    = ["${module.s3_bucket.s3_bucket_arn}/*"]
    }
  }
  depends_on = [aws_macie2_account.enabletest_macie]
}

output "vpc_endpoint_value" {
  value =  "${module.vpc_endpoints.endpoints["s3"]}"
}