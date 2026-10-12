#!/usr/bin/env bash
set -euo pipefail

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_PAGER=""
rm -f /tmp/cloud-risk-lab-ready

log() { printf '[cloud-risk-lab] %s\n' "$*"; }
exists() { "$@" >/dev/null 2>&1; }

ensure_bucket() {
  local bucket="$1"
  if ! exists awslocal s3api head-bucket --bucket "$bucket"; then
    awslocal s3api create-bucket --bucket "$bucket" >/dev/null
  fi
}

put_bucket_tags() {
  local bucket="$1" expected="$2" criticality="$3" classification="$4"
  awslocal s3api put-bucket-tagging --bucket "$bucket" --tagging \
    "TagSet=[{Key=CloudRiskLab,Value=true},{Key=ExpectedFinding,Value=${expected}},{Key=Criticality,Value=${criticality}},{Key=DataClassification,Value=${classification}}]" >/dev/null
}

log "Creating S3 test resources"
ensure_bucket crl-private-data
awslocal s3api put-public-access-block --bucket crl-private-data --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' >/dev/null
put_bucket_tags crl-private-data none high restricted

ensure_bucket crl-public-documents
awslocal s3api put-public-access-block --bucket crl-public-documents --public-access-block-configuration \
  'BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false' >/dev/null
cat >/tmp/public-read-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::crl-public-documents/*"
  }]
}
JSON
awslocal s3api put-bucket-policy --bucket crl-public-documents --policy file:///tmp/public-read-policy.json >/dev/null
put_bucket_tags crl-public-documents S3-002 high confidential

echo 'public lab object' >/tmp/public.txt
awslocal s3api put-object --bucket crl-public-documents --key public.txt --body /tmp/public.txt >/dev/null

ensure_bucket crl-public-upload
awslocal s3api put-public-access-block --bucket crl-public-upload --public-access-block-configuration \
  'BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false' >/dev/null
cat >/tmp/public-write-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicWrite",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::crl-public-upload/*"
  }]
}
JSON
awslocal s3api put-bucket-policy --bucket crl-public-upload --policy file:///tmp/public-write-policy.json >/dev/null
put_bucket_tags crl-public-upload S3-001 high internal

log "Creating IAM test resources"
if ! exists awslocal iam get-user --user-name crl-safe-user; then
  awslocal iam create-user --user-name crl-safe-user --tags Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=none >/dev/null
fi
cat >/tmp/safe-user-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:ListBucket", "s3:GetObject"],
    "Resource": ["arn:aws:s3:::crl-private-data", "arn:aws:s3:::crl-private-data/*"]
  }]
}
JSON
awslocal iam put-user-policy --user-name crl-safe-user --policy-name SafePrivateBucketRead --policy-document file:///tmp/safe-user-policy.json >/dev/null

if ! exists awslocal iam get-user --user-name crl-risky-admin; then
  awslocal iam create-user --user-name crl-risky-admin --tags Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=IAM-001 Key=Criticality,Value=critical >/dev/null
fi
cat >/tmp/risky-admin-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
JSON
awslocal iam put-user-policy --user-name crl-risky-admin --policy-name FullWildcardAccess --policy-document file:///tmp/risky-admin-policy.json >/dev/null

if ! exists awslocal iam get-user --user-name crl-console-no-mfa; then
  awslocal iam create-user --user-name crl-console-no-mfa --tags Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=IAM-005 >/dev/null
fi
if ! exists awslocal iam get-login-profile --user-name crl-console-no-mfa; then
  awslocal iam create-login-profile --user-name crl-console-no-mfa --password 'CloudRisk-Lab_2026!' --password-reset-required >/dev/null
fi

cat >/tmp/public-trust-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "sts:AssumeRole"
  }]
}
JSON
if ! exists awslocal iam get-role --role-name crl-public-trust-role; then
  awslocal iam create-role --role-name crl-public-trust-role --assume-role-policy-document file:///tmp/public-trust-policy.json \
    --tags Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=IAM-004 >/dev/null
fi

log "Creating EC2 and orphaned-resource test data"
VPC_ID="$(awslocal ec2 describe-vpcs --filters Name=tag:Name,Values=crl-vpc --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)"
if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  VPC_ID="$(awslocal ec2 create-vpc --cidr-block 10.77.0.0/16 --query 'Vpc.VpcId' --output text)"
  awslocal ec2 create-tags --resources "$VPC_ID" --tags Key=Name,Value=crl-vpc Key=CloudRiskLab,Value=true >/dev/null
fi

SUBNET_ID="$(awslocal ec2 describe-subnets --filters Name=tag:Name,Values=crl-subnet --query 'Subnets[0].SubnetId' --output text 2>/dev/null || true)"
if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
  SUBNET_ID="$(awslocal ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.77.1.0/24 --availability-zone us-east-1a --query 'Subnet.SubnetId' --output text)"
  awslocal ec2 create-tags --resources "$SUBNET_ID" --tags Key=Name,Value=crl-subnet Key=CloudRiskLab,Value=true >/dev/null
fi

SG_ID="$(awslocal ec2 describe-security-groups --filters Name=group-name,Values=crl-sg Name=vpc-id,Values="$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  SG_ID="$(awslocal ec2 create-security-group --group-name crl-sg --description 'Cloud Risk Lab safe security group' --vpc-id "$VPC_ID" --query 'GroupId' --output text)"
  awslocal ec2 create-tags --resources "$SG_ID" --tags Key=Name,Value=crl-sg Key=CloudRiskLab,Value=true >/dev/null
fi

INSTANCE_ID="$(awslocal ec2 describe-instances --filters Name=tag:Name,Values=crl-used-instance Name=instance-state-name,Values=pending,running,stopped --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)"
if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
  INSTANCE_ID="$(awslocal ec2 run-instances --image-id ami-12345678 --instance-type t3.micro --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" --count 1 --query 'Instances[0].InstanceId' --output text)"
  awslocal ec2 create-tags --resources "$INSTANCE_ID" --tags Key=Name,Value=crl-used-instance Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=none >/dev/null
fi

USED_VOLUME="$(awslocal ec2 describe-volumes --filters Name=tag:Name,Values=crl-used-volume --query 'Volumes[0].VolumeId' --output text 2>/dev/null || true)"
if [[ -z "$USED_VOLUME" || "$USED_VOLUME" == "None" ]]; then
  USED_VOLUME="$(awslocal ec2 create-volume --availability-zone us-east-1a --size 8 --volume-type gp3 --query 'VolumeId' --output text)"
  awslocal ec2 create-tags --resources "$USED_VOLUME" --tags Key=Name,Value=crl-used-volume Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=none >/dev/null
  awslocal ec2 attach-volume --volume-id "$USED_VOLUME" --instance-id "$INSTANCE_ID" --device /dev/sdf >/dev/null
fi

ORPHAN_VOLUME="$(awslocal ec2 describe-volumes --filters Name=tag:Name,Values=crl-orphan-volume --query 'Volumes[0].VolumeId' --output text 2>/dev/null || true)"
if [[ -z "$ORPHAN_VOLUME" || "$ORPHAN_VOLUME" == "None" ]]; then
  ORPHAN_VOLUME="$(awslocal ec2 create-volume --availability-zone us-east-1a --size 20 --volume-type gp3 --query 'VolumeId' --output text)"
  awslocal ec2 create-tags --resources "$ORPHAN_VOLUME" --tags Key=Name,Value=crl-orphan-volume Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=ORPHAN-001 >/dev/null
fi

ORPHAN_EIP="$(awslocal ec2 describe-addresses --filters Name=tag:Name,Values=crl-orphan-eip --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
if [[ -z "$ORPHAN_EIP" || "$ORPHAN_EIP" == "None" ]]; then
  ORPHAN_EIP="$(awslocal ec2 allocate-address --domain vpc --query 'AllocationId' --output text)"
  awslocal ec2 create-tags --resources "$ORPHAN_EIP" --tags Key=Name,Value=crl-orphan-eip Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=ORPHAN-002 >/dev/null
fi

USED_EIP="$(awslocal ec2 describe-addresses --filters Name=tag:Name,Values=crl-used-eip --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
if [[ -z "$USED_EIP" || "$USED_EIP" == "None" ]]; then
  USED_EIP="$(awslocal ec2 allocate-address --domain vpc --query 'AllocationId' --output text)"
  awslocal ec2 create-tags --resources "$USED_EIP" --tags Key=Name,Value=crl-used-eip Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=none >/dev/null
  awslocal ec2 associate-address --allocation-id "$USED_EIP" --instance-id "$INSTANCE_ID" >/dev/null
fi

ORPHAN_ENI="$(awslocal ec2 describe-network-interfaces --filters Name=tag:Name,Values=crl-orphan-eni --query 'NetworkInterfaces[0].NetworkInterfaceId' --output text 2>/dev/null || true)"
if [[ -z "$ORPHAN_ENI" || "$ORPHAN_ENI" == "None" ]]; then
  ORPHAN_ENI="$(awslocal ec2 create-network-interface --subnet-id "$SUBNET_ID" --groups "$SG_ID" --description 'Detached lab interface' --query 'NetworkInterface.NetworkInterfaceId' --output text)"
  awslocal ec2 create-tags --resources "$ORPHAN_ENI" --tags Key=Name,Value=crl-orphan-eni Key=CloudRiskLab,Value=true Key=ExpectedFinding,Value=ORPHAN-003 >/dev/null
fi

touch /tmp/cloud-risk-lab-ready
log "Lab initialization complete"
log "Buckets: $(awslocal s3api list-buckets --query 'length(Buckets)' --output text)"
log "IAM users: $(awslocal iam list-users --query 'length(Users)' --output text)"
log "Volumes: $(awslocal ec2 describe-volumes --query 'length(Volumes)' --output text)"
