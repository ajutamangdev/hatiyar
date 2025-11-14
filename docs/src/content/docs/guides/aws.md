---
title: AWS Enumeration
description: AWS cloud security and infrastructure enumeration guide
---

The Hatiyar AWS enumeration suite provides deep visibility into your AWS infrastructure across multiple services. Each module focuses on specific AWS services, providing detailed resource discovery, configuration analysis, and security assessments.

## Available Modules

| Module | Description |
|--------|-------------|
| **AWS Comprehensive Enumeration** | Complete AWS security audit across all services |
| **EC2** | Compute instances, security groups, volumes, and AMIs |
| **S3** | Storage buckets, encryption, policies, and ACLs |
| **IAM** | Users, roles, groups, policies, and MFA status |
| **Lambda** | Serverless functions, layers, and event sources |
| **Secrets Manager & Parameter Store** | Secrets and parameters with rotation analysis |
| **Database** | RDS, Aurora, DynamoDB, and ElastiCache |
| **Container Services** | ECS, EKS, and ECR with image scanning |
| **Route53** | DNS zones, records, health checks, and DNSSEC |
| **Amplify** | Applications, branches, domains, and CI/CD | 

### Getting Started

```bash
# Start hatiyar shell
hatiyar shell

# List available AWS modules
hatiyar> ls cloud.aws

# Use a specific module
hatiyar> use cloud.aws.ec2
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

Then use in hatiyar:
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

Set credentials directly in hatiyar:
```bash
set ACCESS_KEY your-access-key
set SECRET_KEY your-secret-key
```

### 3. Testing with LocalStack (Local AWS Emulation)

For development and testing purposes, you can use **LocalStack** to emulate AWS services locally without using real AWS credentials or resources.

#### Setup LocalStack

**Prerequisites:**
- Docker installed and running

**Start LocalStack:**
```bash
docker run -d \
  --name localstack \
  -p 4566:4566 \
  localstack/localstack:latest
```

Or using Docker Compose (`docker-compose.yml`):
```yaml
version: '3.8'
services:
  localstack:
    image: localstack/localstack:latest
    ports:
      - "4566:4566"
```

Start with:
```bash
docker-compose up -d
```

**Verify LocalStack is Running:**

```bash
# Check if container is running
docker ps

# Check health endpoint
curl http://localhost:4566/_localstack/health
```

Expected output should show the container is running and health check returns a success response.

#### Configure Fake AWS Credentials with Profile

Create a local AWS profile for LocalStack:

```bash
# Create a new AWS profile named 'local'
aws configure --profile local
```

Provide the following when prompted:
```
AWS Access Key ID [None]: fake
AWS Secret Access Key [None]: fake
Default region name [None]: us-east-1
Default output format [None]: json
```

Then configure the LocalStack endpoint URL for this profile:

```bash
aws configure set ENDPOINT_URL http://localhost:4566 --profile local
```

**Verify the configuration** (should be saved in `~/.aws/config` and `~/.aws/credentials`):

```bash
# View the profile configuration
cat ~/.aws/config
cat ~/.aws/credentials
```

#### Use the Profile in hatiyar

In the hatiyar shell, simply set the profile:

```bash
hatiyar> set AWS_PROFILE local
```

This will automatically use the LocalStack endpoint URL and credentials you configured above.

#### Test EC2 Enumeration with LocalStack

Once you create some emulated aws resources in LocalStack, you can perform enumeration.

```bash

# Load EC2 module
hatiyar> use cloud.aws.ec2

# Set the local profile
hatiyar> set AWS_PROFILE local

# View configuration to verify
hatiyar> show options

# Run enumeration
hatiyar> run
```

The enumeration will use the endpoint URL (`http://localhost:4566`) and credentials from your `local` AWS profile automatically.

#### Cleanup LocalStack

```bash
# Stop and remove LocalStack container
docker stop localstack
docker rm localstack

# Or with Docker Compose:
docker-compose down
```

---

## EC2 - Quick Start

### Interactive Shell Method

```bash
# Start hatiyar shell
hatiyar shell

# List cloud modules
hatiyar> ls cloud

# Navigate to AWS namespace
hatiyar> use cloud.aws


# Load EC2 module
hatiyar> use cloud.aws.ec2

# View module options
hatiyar> show options

# Set AWS region
hatiyar> set AWS_REGION us-east-1

hatiyar>set AWS_PROFILE <name-of-aws-profie> or set  SECRET_KEY and ACCESS_KEY

# Run enumeration
hatiyar> run
```


## EC2 Module Options

View all available options:

```bash
hatiyar> use cloud.aws.ec2
hatiyar> show options
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

Want to add support for additional AWS services? See our [Contributing Guide](/hatiyar/guides/contribution/)

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
