"""AWS S3 Enumeration Module"""

from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from hatiyar.core.module_base import ModuleBase, ModuleType
from hatiyar.utils.output import save_json_results

console = Console()


class Module(ModuleBase):
    """AWS S3 bucket enumeration including encryption, versioning, policies, and public access analysis."""

    NAME = "s3_enumeration"
    DESCRIPTION = "AWS S3 bucket and configuration enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_OBJECTS": False,
        "MAX_OBJECTS_PER_BUCKET": 100,
        "CHECK_PUBLIC_ACCESS": True,
        "OUTPUT_FILE": "s3_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.s3_client = None
        self.s3_resource = None
        self.data = {
            "buckets": [],
            "total_buckets": 0,
            "public_buckets": [],
            "encrypted_buckets": [],
            "versioned_buckets": [],
            "website_buckets": [],
            "security_findings": [],
        }

    def initialize_client(self) -> bool:
        """Initialize AWS S3 client with multiple credential options"""
        try:
            session_kwargs = {
                "region_name": self.options.get("AWS_REGION", "us-east-1")
            }

            if self.options.get("AWS_PROFILE"):
                session_kwargs["profile_name"] = self.options["AWS_PROFILE"]
                console.print(
                    f"[dim]Using AWS profile: {self.options['AWS_PROFILE']}[/dim]"
                )

            elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
                session_kwargs["aws_access_key_id"] = self.options["ACCESS_KEY"]
                session_kwargs["aws_secret_access_key"] = self.options["SECRET_KEY"]
                if self.options.get("SESSION_TOKEN"):
                    session_kwargs["aws_session_token"] = self.options["SESSION_TOKEN"]

            else:
                console.print("[dim]Using default AWS credentials[/dim]")

            session = boto3.Session(**session_kwargs)
            self.s3_client = session.client("s3")
            self.s3_resource = session.resource("s3")

            # Test credentials
            self.s3_client.list_buckets()
            console.print("[green]✓[/green] Connected to AWS S3")
            return True

        except NoCredentialsError:
            console.print(
                "[red]✗[/red] No AWS credentials found. Configure AWS CLI, set profile, or provide credentials."
            )
            console.print(
                "[yellow]Hint:[/yellow] Set ACCESS_KEY and SECRET_KEY options, or configure ~/.aws/credentials"
            )
            return False
        except PartialCredentialsError:
            console.print("[red]✗[/red] Incomplete AWS credentials provided.")
            return False
        except ClientError as e:
            if e.response["Error"]["Code"] == "UnauthorizedOperation":
                console.print(
                    f"[red]✗[/red] Unauthorized: {e.response['Error']['Message']}"
                )
            else:
                console.print(
                    f"[red]✗[/red] AWS Error: {e.response['Error']['Message']}"
                )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize S3 client: {str(e)}")
            return False

    def _get_bucket_location(self, bucket_name: str) -> str:
        """Get bucket region/location"""
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint")
            # us-east-1 returns None
            return location if location else "us-east-1"
        except Exception:
            return "unknown"

    def _get_bucket_encryption(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket encryption configuration"""
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            return {
                "enabled": True,
                "rules": [
                    {
                        "sse_algorithm": rule.get(
                            "ApplyServerSideEncryptionByDefault", {}
                        ).get("SSEAlgorithm"),
                        "kms_master_key_id": rule.get(
                            "ApplyServerSideEncryptionByDefault", {}
                        ).get("KMSMasterKeyID"),
                        "bucket_key_enabled": rule.get("BucketKeyEnabled", False),
                    }
                    for rule in rules
                ],
            }
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                return {"enabled": False, "rules": []}
            return {"enabled": False, "error": str(e)}
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def _get_bucket_versioning(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket versioning configuration"""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            return {
                "status": response.get("Status", "Disabled"),
                "mfa_delete": response.get("MFADelete", "Disabled"),
            }
        except Exception:
            return {"status": "Unknown", "error": "Failed to retrieve versioning"}

    def _get_bucket_lifecycle(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Get bucket lifecycle configuration"""
        try:
            response = self.s3_client.get_bucket_lifecycle_configuration(
                Bucket=bucket_name
            )
            rules = []
            for rule in response.get("Rules", []):
                rules.append(
                    {
                        "id": rule.get("ID"),
                        "status": rule.get("Status"),
                        "prefix": rule.get(
                            "Prefix", rule.get("Filter", {}).get("Prefix", "")
                        ),
                        "transitions": rule.get("Transitions", []),
                        "expiration": rule.get("Expiration", {}),
                        "noncurrent_version_transitions": rule.get(
                            "NoncurrentVersionTransitions", []
                        ),
                        "noncurrent_version_expiration": rule.get(
                            "NoncurrentVersionExpiration", {}
                        ),
                    }
                )
            return rules
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                return []
            return []
        except Exception:
            return []

    def _get_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket policy"""
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            return {
                "exists": True,
                "policy": response.get("Policy"),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {"exists": False}
            return {"exists": False, "error": str(e)}
        except Exception as e:
            return {"exists": False, "error": str(e)}

    def _get_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket ACL"""
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = []
            for grant in response.get("Grants", []):
                grantee = grant.get("Grantee", {})
                grants.append(
                    {
                        "permission": grant.get("Permission"),
                        "grantee_type": grantee.get("Type"),
                        "grantee_id": grantee.get("ID"),
                        "grantee_display_name": grantee.get("DisplayName"),
                        "grantee_uri": grantee.get("URI"),
                    }
                )
            return {
                "owner": response.get("Owner", {}),
                "grants": grants,
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Get public access block configuration"""
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})
            return {
                "enabled": True,
                "block_public_acls": config.get("BlockPublicAcls", False),
                "ignore_public_acls": config.get("IgnorePublicAcls", False),
                "block_public_policy": config.get("BlockPublicPolicy", False),
                "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {
                    "enabled": False,
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                }
            return {"enabled": False, "error": str(e)}
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def _get_bucket_logging(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket logging configuration"""
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = response.get("LoggingEnabled", {})
            if logging_enabled:
                return {
                    "enabled": True,
                    "target_bucket": logging_enabled.get("TargetBucket"),
                    "target_prefix": logging_enabled.get("TargetPrefix"),
                }
            return {"enabled": False}
        except Exception:
            return {"enabled": False, "error": "Failed to retrieve logging"}

    def _get_bucket_website(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket website configuration"""
        try:
            response = self.s3_client.get_bucket_website(Bucket=bucket_name)
            return {
                "enabled": True,
                "index_document": response.get("IndexDocument", {}).get("Suffix"),
                "error_document": response.get("ErrorDocument", {}).get("Key"),
                "redirect_all_requests_to": response.get("RedirectAllRequestsTo", {}),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                return {"enabled": False}
            return {"enabled": False, "error": str(e)}
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def _get_bucket_cors(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Get bucket CORS configuration"""
        try:
            response = self.s3_client.get_bucket_cors(Bucket=bucket_name)
            return response.get("CORSRules", [])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchCORSConfiguration":
                return []
            return []
        except Exception:
            return []

    def _get_bucket_replication(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket replication configuration"""
        try:
            response = self.s3_client.get_bucket_replication(Bucket=bucket_name)
            return {
                "enabled": True,
                "role": response.get("ReplicationConfiguration", {}).get("Role"),
                "rules": response.get("ReplicationConfiguration", {}).get("Rules", []),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
                return {"enabled": False}
            return {"enabled": False, "error": str(e)}
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def _get_bucket_tagging(self, bucket_name: str) -> List[Dict[str, str]]:
        """Get bucket tags"""
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            return response.get("TagSet", [])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                return []
            return []
        except Exception:
            return []

    def _enumerate_bucket_objects(self, bucket_name: str) -> Dict[str, Any]:
        """Enumerate objects in a bucket (limited)"""
        try:
            max_objects = self.options.get("MAX_OBJECTS_PER_BUCKET", 100)
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name, MaxKeys=max_objects
            )

            objects = []
            for obj in response.get("Contents", []):
                objects.append(
                    {
                        "key": obj.get("Key"),
                        "size": obj.get("Size"),
                        "last_modified": obj.get("LastModified").isoformat()
                        if obj.get("LastModified")
                        else None,
                        "storage_class": obj.get("StorageClass"),
                        "etag": obj.get("ETag"),
                    }
                )

            return {
                "total_objects": response.get("KeyCount", 0),
                "is_truncated": response.get("IsTruncated", False),
                "objects": objects,
            }
        except Exception as e:
            return {"error": str(e)}

    def _check_bucket_security(self, bucket_info: Dict[str, Any]) -> List[str]:
        """Check bucket for security issues"""
        findings = []
        bucket_name = bucket_info["name"]

        # Check encryption
        if not bucket_info.get("encryption", {}).get("enabled"):
            findings.append(f"Bucket '{bucket_name}' does not have encryption enabled")

        # Check versioning
        if bucket_info.get("versioning", {}).get("status") != "Enabled":
            findings.append(f"Bucket '{bucket_name}' does not have versioning enabled")

        # Check public access block
        public_access = bucket_info.get("public_access_block", {})
        if not public_access.get("enabled") or not all(
            [
                public_access.get("block_public_acls"),
                public_access.get("ignore_public_acls"),
                public_access.get("block_public_policy"),
                public_access.get("restrict_public_buckets"),
            ]
        ):
            findings.append(
                f"Bucket '{bucket_name}' may allow public access (public access block not fully configured)"
            )

        # Check ACL for public grants
        acl = bucket_info.get("acl", {})
        for grant in acl.get("grants", []):
            grantee_uri = grant.get("grantee_uri") or ""
            if "AllUsers" in grantee_uri or "AuthenticatedUsers" in grantee_uri:
                findings.append(
                    f"Bucket '{bucket_name}' has public ACL grants: {grant.get('permission')}"
                )

        # Check logging
        if not bucket_info.get("logging", {}).get("enabled"):
            findings.append(
                f"Bucket '{bucket_name}' does not have access logging enabled"
            )

        return findings

    def enumerate_buckets(self):
        """Enumerate all S3 buckets with detailed configuration"""
        console.print("\n[bold cyan]═══ Enumerating S3 Buckets ═══[/bold cyan]")

        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])
            self.data["total_buckets"] = len(buckets)

            console.print(f"[dim]Found {len(buckets)} bucket(s)[/dim]\n")

            for idx, bucket in enumerate(buckets, 1):
                bucket_name = bucket["Name"]
                creation_date = (
                    bucket["CreationDate"].isoformat()
                    if bucket.get("CreationDate")
                    else None
                )

                # Collect all bucket configurations
                bucket_info = {
                    "name": bucket_name,
                    "creation_date": creation_date,
                    "location": self._get_bucket_location(bucket_name),
                    "encryption": self._get_bucket_encryption(bucket_name),
                    "versioning": self._get_bucket_versioning(bucket_name),
                    "lifecycle": self._get_bucket_lifecycle(bucket_name),
                    "policy": self._get_bucket_policy(bucket_name),
                    "acl": self._get_bucket_acl(bucket_name),
                    "public_access_block": self._get_public_access_block(bucket_name),
                    "logging": self._get_bucket_logging(bucket_name),
                    "website": self._get_bucket_website(bucket_name),
                    "cors": self._get_bucket_cors(bucket_name),
                    "replication": self._get_bucket_replication(bucket_name),
                    "tags": self._get_bucket_tagging(bucket_name),
                }

                # Enumerate objects if enabled
                if self.options.get("ENUMERATE_OBJECTS"):
                    bucket_info["objects"] = self._enumerate_bucket_objects(bucket_name)

                # Build comprehensive display
                encryption_status = (
                    "✓ Enabled"
                    if bucket_info["encryption"]["enabled"]
                    else "✗ Disabled"
                )
                encryption_color = (
                    "green" if bucket_info["encryption"]["enabled"] else "red"
                )

                versioning_status = bucket_info["versioning"]["status"]
                versioning_color = (
                    "green" if versioning_status == "Enabled" else "yellow"
                )

                public_access = bucket_info["public_access_block"]
                is_fully_blocked = public_access.get("enabled") and all(
                    [
                        public_access.get("block_public_acls"),
                        public_access.get("ignore_public_acls"),
                        public_access.get("block_public_policy"),
                        public_access.get("restrict_public_buckets"),
                    ]
                )
                public_status = (
                    "✓ Blocked" if is_fully_blocked else "⚠ Not Fully Blocked"
                )
                public_color = "green" if is_fully_blocked else "yellow"

                logging_status = (
                    "✓ Enabled" if bucket_info["logging"]["enabled"] else "✗ Disabled"
                )
                logging_color = (
                    "green" if bucket_info["logging"]["enabled"] else "yellow"
                )

                details = f"""[bold cyan]Bucket {idx}/{len(buckets)}:[/bold cyan] [bold]{bucket_name}[/bold]
[bold]Created:[/bold] {creation_date or "N/A"}
[bold]Region:[/bold] {bucket_info["location"]}

[bold cyan]Security Configuration:[/bold cyan]
  • Encryption: [{encryption_color}]{encryption_status}[/{encryption_color}]"""

                if bucket_info["encryption"]["enabled"]:
                    for rule in bucket_info["encryption"]["rules"]:
                        algo = rule.get("sse_algorithm", "N/A")
                        details += f"\n    Algorithm: {algo}"
                        if rule.get("kms_master_key_id"):
                            details += (
                                f"\n    KMS Key: {rule['kms_master_key_id'][:50]}..."
                            )
                        if rule.get("bucket_key_enabled"):
                            details += "\n    Bucket Key: Enabled"

                details += f"\n  • Versioning: [{versioning_color}]{versioning_status}[/{versioning_color}]"
                if bucket_info["versioning"]["mfa_delete"] != "Disabled":
                    details += (
                        f"\n    MFA Delete: {bucket_info['versioning']['mfa_delete']}"
                    )

                details += f"\n  • Public Access: [{public_color}]{public_status}[/{public_color}]"
                if not is_fully_blocked:
                    details += f"\n    Block Public ACLs: {public_access.get('block_public_acls', False)}"
                    details += f"\n    Ignore Public ACLs: {public_access.get('ignore_public_acls', False)}"
                    details += f"\n    Block Public Policy: {public_access.get('block_public_policy', False)}"
                    details += f"\n    Restrict Public Buckets: {public_access.get('restrict_public_buckets', False)}"

                details += f"\n  • Access Logging: [{logging_color}]{logging_status}[/{logging_color}]"
                if bucket_info["logging"]["enabled"]:
                    details += f"\n    Target Bucket: {bucket_info['logging']['target_bucket']}"
                    if bucket_info["logging"].get("target_prefix"):
                        details += (
                            f"\n    Prefix: {bucket_info['logging']['target_prefix']}"
                        )

                # Bucket Policy
                details += "\n\n[bold cyan]Policies & Permissions:[/bold cyan]"
                details += f"\n  • Bucket Policy: {'✓ Configured' if bucket_info['policy']['exists'] else '✗ None'}"

                # ACL
                acl = bucket_info["acl"]
                if "owner" in acl:
                    details += (
                        f"\n  • ACL Owner: {acl['owner'].get('DisplayName', 'N/A')}"
                    )
                grant_count = len(acl.get("grants", []))
                details += f"\n  • ACL Grants: {grant_count} permission(s)"

                # Check for public grants
                public_grants = []
                for grant in acl.get("grants", []):
                    grantee_uri = grant.get("grantee_uri") or ""
                    if "AllUsers" in grantee_uri or "AuthenticatedUsers" in grantee_uri:
                        public_grants.append(grant)

                if public_grants:
                    details += "\n    [yellow]⚠ Public Grants Found:[/yellow]"
                    for grant in public_grants[:3]:  # Show first 3
                        grantee_uri = grant.get("grantee_uri", "")
                        permission = grant.get("permission", "N/A")
                        grantee_type = (
                            "All Users"
                            if "AllUsers" in grantee_uri
                            else "Authenticated Users"
                        )
                        details += f"\n      - {grantee_type}: {permission}"
                    if len(public_grants) > 3:
                        details += f"\n      ... and {len(public_grants) - 3} more"

                # Additional Features
                details += "\n\n[bold cyan]Additional Features:[/bold cyan]"

                # Website Hosting
                website_status = (
                    "✓ Enabled" if bucket_info["website"]["enabled"] else "✗ Disabled"
                )
                website_color = "cyan" if bucket_info["website"]["enabled"] else "dim"
                details += f"\n  • Website Hosting: [{website_color}]{website_status}[/{website_color}]"
                if bucket_info["website"]["enabled"]:
                    if bucket_info["website"].get("index_document"):
                        details += (
                            f"\n    Index: {bucket_info['website']['index_document']}"
                        )
                    if bucket_info["website"].get("error_document"):
                        details += (
                            f"\n    Error: {bucket_info['website']['error_document']}"
                        )

                # Replication
                replication_status = (
                    "✓ Enabled"
                    if bucket_info["replication"]["enabled"]
                    else "✗ Disabled"
                )
                replication_color = (
                    "cyan" if bucket_info["replication"]["enabled"] else "dim"
                )
                details += f"\n  • Replication: [{replication_color}]{replication_status}[/{replication_color}]"
                if bucket_info["replication"]["enabled"]:
                    rule_count = len(bucket_info["replication"].get("rules", []))
                    details += f"\n    Rules: {rule_count}"

                # Lifecycle
                lifecycle_count = len(bucket_info["lifecycle"])
                if lifecycle_count > 0:
                    details += f"\n  • Lifecycle Rules: {lifecycle_count} configured"
                else:
                    details += "\n  • Lifecycle Rules: None"

                # CORS
                cors_count = len(bucket_info["cors"])
                if cors_count > 0:
                    details += f"\n  • CORS Rules: {cors_count} configured"
                else:
                    details += "\n  • CORS Rules: None"

                # Tags
                tag_count = len(bucket_info["tags"])
                if tag_count > 0:
                    details += f"\n  • Tags: {tag_count} tag(s)"
                    for tag in bucket_info["tags"][:3]:  # Show first 3
                        details += f"\n    {tag['Key']}: {tag['Value']}"
                    if tag_count > 3:
                        details += f"\n    ... and {tag_count - 3} more"
                else:
                    details += "\n  • Tags: None"

                # Objects (if enumerated)
                if self.options.get("ENUMERATE_OBJECTS") and "objects" in bucket_info:
                    obj_data = bucket_info["objects"]
                    if "error" not in obj_data:
                        details += "\n\n[bold cyan]Objects:[/bold cyan]"
                        details += f"\n  • Total Objects: {obj_data['total_objects']}"
                        if obj_data["is_truncated"]:
                            details += f" (showing first {self.options.get('MAX_OBJECTS_PER_BUCKET', 100)})"

                        if obj_data["objects"]:
                            total_size = sum(
                                obj.get("size", 0) for obj in obj_data["objects"]
                            )
                            size_mb = total_size / (1024 * 1024)
                            details += f"\n  • Total Size: {size_mb:.2f} MB"
                            details += "\n  • Sample Objects:"
                            for obj in obj_data["objects"][:3]:
                                obj_size = obj.get("size", 0) / 1024  # KB
                                details += f"\n    - {obj['key']} ({obj_size:.1f} KB)"
                            if len(obj_data["objects"]) > 3:
                                details += (
                                    f"\n    ... and {len(obj_data['objects']) - 3} more"
                                )

                # Display the bucket details in a panel
                from rich.panel import Panel

                console.print(Panel(details, expand=False, border_style="cyan"))

                # Check for security issues
                if self.options.get("CHECK_PUBLIC_ACCESS"):
                    findings = self._check_bucket_security(bucket_info)
                    if findings:
                        self.data["security_findings"].extend(findings)

                # Track categorized buckets
                if bucket_info["encryption"]["enabled"]:
                    self.data["encrypted_buckets"].append(bucket_name)
                if bucket_info["versioning"]["status"] == "Enabled":
                    self.data["versioned_buckets"].append(bucket_name)
                if bucket_info["website"]["enabled"]:
                    self.data["website_buckets"].append(bucket_name)

                # Check if bucket might be public
                if not is_fully_blocked:
                    self.data["public_buckets"].append(bucket_name)

                self.data["buckets"].append(bucket_info)

            console.print(
                f"\n[green]✓ Enumerated {len(buckets)} S3 bucket(s) with detailed configuration[/green]"
            )

        except ClientError as e:
            console.print(
                f"[red]✗ Error enumerating buckets: {e.response['Error']['Message']}[/red]"
            )
        except Exception as e:
            console.print(f"[red]✗ Unexpected error: {str(e)}[/red]")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        # If no output file specified, generate default filename with timestamp
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"s3_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Add metadata

            output_data = {
                "metadata": {
                    "module": self.NAME,
                    "version": self.VERSION,
                    "timestamp": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "profile": self.options.get("AWS_PROFILE", "default"),
                },
                "summary": {
                    "total_buckets": self.data["total_buckets"],
                    "encrypted_buckets": len(self.data["encrypted_buckets"]),
                    "versioned_buckets": len(self.data["versioned_buckets"]),
                    "website_buckets": len(self.data["website_buckets"]),
                    "potentially_public_buckets": len(self.data["public_buckets"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "data": self.data,
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓ Results saved to: {output_file}[/green]")
            return str(output_path)

        except (IOError, ValueError) as e:
            console.print(f"[red]✗ {e}[/red]")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute S3 enumeration"""

        panel = Panel(
            "[bold cyan]AWS S3 Bucket Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting buckets with encryption, versioning, policies, ACLs, and security configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "status": "failed",
                "message": "Failed to initialize S3 client",
            }

        # Execute bucket enumeration
        self.enumerate_buckets()

        # Save results to JSON file
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(f"[bold]Total Buckets:[/bold] {self.data['total_buckets']}")
        console.print(
            f"  [green]✓[/green] Encrypted: {len(self.data['encrypted_buckets'])}/{self.data['total_buckets']} | "
            f"Versioned: {len(self.data['versioned_buckets'])}/{self.data['total_buckets']} | "
            f"Website Hosting: {len(self.data['website_buckets'])}/{self.data['total_buckets']}"
        )

        # Show buckets with full security configuration
        fully_secure = []
        for bucket_info in self.data["buckets"]:
            if (
                bucket_info.get("encryption", {}).get("enabled")
                and bucket_info.get("versioning", {}).get("status") == "Enabled"
                and bucket_info.get("logging", {}).get("enabled")
            ):
                fully_secure.append(bucket_info["name"])

        if fully_secure:
            console.print("\n[bold green]Buckets with Full Security:[/bold green]")
            for bucket_name in fully_secure:
                console.print(
                    f"  [green]✓[/green] {bucket_name} (Encryption + Versioning + Logging)"
                )

        # Show potentially public buckets as warning
        if self.data["public_buckets"]:
            console.print(
                f"\n[bold yellow]⚠ Potentially Public Buckets:[/bold yellow] {len(self.data['public_buckets'])}"
            )
            for bucket_name in self.data["public_buckets"]:
                console.print(f"  [yellow]→[/yellow] {bucket_name}")

        return {
            "success": True,
            "status": "completed",
            "message": f"Enumeration complete. Results saved to {output_file}",
            "output_file": output_file,
            "summary": {
                "total_buckets": self.data["total_buckets"],
                "encrypted_buckets": len(self.data["encrypted_buckets"]),
                "versioned_buckets": len(self.data["versioned_buckets"]),
                "website_buckets": len(self.data["website_buckets"]),
                "potentially_public_buckets": len(self.data["public_buckets"]),
                "security_findings": len(self.data["security_findings"]),
            },
        }
