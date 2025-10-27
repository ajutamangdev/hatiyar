---
title: AWS Enumeration
description: AWS cloud security and infrastructure enumeration guide
---

The pysecfw AWS enumeration suite provides deep visibility into your AWS infrastructure across multiple services. Each module focuses on specific AWS services, providing detailed resource discovery, configuration analysis, and security assessments.

### Available Modules

| Module |Description |
|--------|-------------|
| **EC2** | EC2 instances, VPCs, networking, storage, and compute resources|


> Others coming soon 

### Getting Started

```bash
# Start pysecfw shell
pysecfw shell

# List available AWS modules
pysecfw> ls cloud.aws

# Use a specific module
pysecfw> use cloud.aws.ec2
```

---

# EC2 Enumeration Module

Comprehensive EC2, VPC, and networking resource discovery for security assessments and infrastructure auditing.

## General AWS Setup

This setup applies to all AWS enumeration modules (EC2, S3, RDS, IAM, etc.)

### 1. Install AWS SDK

```bash
pip install boto3
```

### 2. Configure AWS Credentials

Choose one of these authentication methods:

#### Option A: AWS CLI Configuration (Recommended)

```bash
aws configure
```

Provide:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., `us-east-1`)
- Output format (optional)

#### Option B: AWS Profile

```bash
aws configure --profile myprofile
```

Then use in pysecfw:
```bash
set AWS_PROFILE myprofile
```

#### Option C: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

#### Option D: Direct Credentials (Not Recommended for Production)

Set credentials directly in pysecfw:
```bash
set ACCESS_KEY your-access-key
set SECRET_KEY your-secret-key
```
---

## EC2 - Quick Start

### Interactive Shell Method

```bash
# Start pysecfw shell
pysecfw shell

# List cloud modules
pysecfw> ls cloud

# Navigate to AWS namespace
pysecfw> use cloud.aws


# Load EC2 module
pysecfw> use cloud.aws.ec2

# View module options
pysecfw> show options

# Set AWS region
pysecfw> set AWS_REGION us-east-1

pysecfw>set AWS_PROFILE <name-of-aws-profie> or set  SECRET_KEY and ACCESS_KEY

# Run enumeration
pysecfw> run
```


## EC2 Module Options

View all available options:

```bash
pysecfw> use cloud.aws.ec2
pysecfw> show options
```

### Configuration Options

| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| `AWS_REGION` | `us-east-1` | Yes | AWS region to enumerate |
| `AWS_PROFILE` | *(empty)* | No | AWS CLI profile name |
| `ACCESS_KEY` | *(empty)* | No | AWS Access Key ID |
| `SECRET_KEY` | *(empty)* | No | AWS Secret Access Key |
| `SESSION_TOKEN` | *(empty)* | No | AWS Session Token (for temporary credentials) |
| `ENUMERATE_INSTANCES` | `True` | No | Enable instance-centric enumeration |
| `OUTPUT_FILE` | `ec2_enumeration_results.json` | No | Output JSON file path |

### Setting Options

```bash
# Set AWS region
set AWS_REGION us-west-2

# Use AWS profile
set AWS_PROFILE production

# Custom output file
set OUTPUT_FILE my_ec2_audit_2024.json

```
## Common AWS Troubleshooting

These troubleshooting tips apply to all AWS enumeration modules.

### Connection Issues

**Problem**: `No AWS credentials found`

**Solution**:
1. Configure AWS CLI: `aws configure`
2. Or set credentials in module:
   ```bash
   set ACCESS_KEY your-key
   set SECRET_KEY your-secret
   ```

---

**Problem**: `UnauthorizedOperation: You are not authorized to perform this operation`

**Solution**: Add required IAM permissions (see Prerequisites section)

---

**Problem**: `Could not connect to the endpoint URL`

**Solution**: Check your region setting:
```bash
set AWS_REGION us-east-1  # Use correct region
```

### Permission Issues

**Problem**: Some resources not appearing in results

**Solution**: Ensure your IAM role/user has all required permissions:
```bash
# Test specific permission
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups --region us-east-1
aws ssm describe-instance-information --region us-east-1
```

### Output Issues

**Problem**: JSON file not created

**Solution**: Check file path and permissions:
```bash
# Use absolute path
set OUTPUT_FILE /tmp/ec2_audit.json

# Or ensure current directory is writable
ls -la
```

---

**Problem**: Output file is empty or incomplete

**Solution**: 
1. Check console for errors during enumeration
2. Enable verbose mode: `set VERBOSE True`
3. Verify AWS credentials have read permissions

---

## Contributing New AWS Modules

Want to add support for additional AWS services? See our [Contributing Guide](/pysecfw/guides/contribution/)

---

## Security Disclaimer

⚠️ **Authorization Required**

These AWS enumeration tools should only be used on AWS accounts you own or have explicit permission to audit. Always:
- Obtain written authorization before enumerating third-party AWS accounts
- Follow your organization's security policies and procedures
- Comply with AWS Acceptable Use Policy and Terms of Service
- Use read-only IAM credentials when possible (principle of least privilege)
- Protect enumeration results as they contain sensitive infrastructure information
- Store credentials securely and never commit them to version control
- Rotate access keys regularly and follow AWS security best practices

The developers assume no liability for misuse of these tools. Use responsibly and ethically.
