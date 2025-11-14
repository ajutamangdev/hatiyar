"""AWS Secrets Manager & Parameter Store Enumeration Module"""

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
    """AWS Secrets Manager and Parameter Store enumeration with rotation and encryption analysis."""

    NAME = "secrets_enumeration"
    DESCRIPTION = "AWS Secrets Manager and Parameter Store enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_SECRETS": True,
        "ENUMERATE_PARAMETERS": True,
        "RETRIEVE_VALUES": False,
        "CHECK_ROTATION": True,
        "OUTPUT_FILE": "secrets_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.secrets_client = None
        self.ssm_client = None
        self.kms_client = None
        self.data = {
            "secrets": [],
            "parameters": [],
            "kms_keys": [],
            "security_findings": [],
            "total_secrets": 0,
            "total_parameters": 0,
            "secrets_with_rotation": [],
            "secrets_without_rotation": [],
            "encrypted_parameters": [],
        }

    def initialize_client(self) -> bool:
        """Initialize AWS clients with multiple credential options"""
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
            self.secrets_client = session.client("secretsmanager")
            self.ssm_client = session.client("ssm")
            self.kms_client = session.client("kms")

            # Test credentials
            self.secrets_client.list_secrets(MaxResults=1)
            console.print(
                f"[green]✓[/green] Connected to AWS Secrets Manager in region: {self.options['AWS_REGION']}"
            )
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
                console.print("[red]✗[/red] Access denied. Check IAM permissions.")
                console.print(
                    "[yellow]Required:[/yellow] secretsmanager:ListSecrets, ssm:DescribeParameters"
                )
            else:
                console.print(
                    f"[red]✗[/red] AWS error: {e.response['Error']['Message']}"
                )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize clients: {str(e)}")
            return False

    def _get_secret_details(self, secret_arn: str, secret_name: str) -> Dict[str, Any]:
        """Get detailed information about a secret"""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_arn)

            secret_info = {
                "arn": secret_arn,
                "name": secret_name,
                "description": response.get("Description", ""),
                "kms_key_id": response.get("KmsKeyId", ""),
                "rotation_enabled": response.get("RotationEnabled", False),
                "rotation_lambda_arn": response.get("RotationLambdaARN", ""),
                "rotation_rules": response.get("RotationRules", {}),
                "last_rotated_date": str(response.get("LastRotatedDate", ""))
                if response.get("LastRotatedDate")
                else "",
                "last_changed_date": str(response.get("LastChangedDate", ""))
                if response.get("LastChangedDate")
                else "",
                "last_accessed_date": str(response.get("LastAccessedDate", ""))
                if response.get("LastAccessedDate")
                else "",
                "deleted_date": str(response.get("DeletedDate", ""))
                if response.get("DeletedDate")
                else "",
                "tags": response.get("Tags", []),
                "version_ids_to_stages": response.get("VersionIdsToStages", {}),
                "created_date": str(response.get("CreatedDate", ""))
                if response.get("CreatedDate")
                else "",
            }

            # Get resource policy if exists
            try:
                policy_response = self.secrets_client.get_resource_policy(
                    SecretId=secret_arn
                )
                secret_info["resource_policy"] = policy_response.get("ResourcePolicy")
            except ClientError:
                secret_info["resource_policy"] = None

            # Optionally retrieve secret value
            if self.options.get("RETRIEVE_VALUES"):
                try:
                    value_response = self.secrets_client.get_secret_value(
                        SecretId=secret_arn
                    )
                    secret_info["secret_string"] = value_response.get(
                        "SecretString", ""
                    )
                    secret_info["secret_binary"] = str(
                        value_response.get("SecretBinary", "")
                    )
                except ClientError as e:
                    secret_info["secret_value_error"] = str(e)

            return secret_info

        except Exception as e:
            return {"arn": secret_arn, "name": secret_name, "error": str(e)}

    def enumerate_secrets(self):
        """Enumerate all Secrets Manager secrets"""
        if not self.options.get("ENUMERATE_SECRETS"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Secrets Manager Secrets ═══[/bold cyan]"
        )

        try:
            paginator = self.secrets_client.get_paginator("list_secrets")
            secret_count = 0

            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    secret_count += 1
                    secret_name = secret.get("Name", "")
                    secret_arn = secret.get("ARN", "")

                    console.print(
                        f"\n[cyan]Secret {secret_count}:[/cyan] {secret_name}"
                    )

                    # Get detailed information
                    secret_info = self._get_secret_details(secret_arn, secret_name)
                    self.data["secrets"].append(secret_info)

                    # Track rotation status
                    if secret_info.get("rotation_enabled"):
                        self.data["secrets_with_rotation"].append(secret_name)
                    else:
                        self.data["secrets_without_rotation"].append(secret_name)

                    # Display secret details in panel
                    self._display_secret_panel(secret_info)

                    # Check for security issues
                    findings = self._check_secret_security(secret_info)
                    if findings:
                        self.data["security_findings"].extend(findings)

            self.data["total_secrets"] = secret_count
            console.print(f"\n[green]✓[/green] Found {secret_count} secrets")

        except ClientError as e:
            console.print(
                f"[red]✗[/red] Error enumerating secrets: {e.response['Error']['Message']}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _display_secret_panel(self, secret_info: Dict[str, Any]):
        """Display secret information in a formatted panel"""
        rotation_status = (
            "🔄 Enabled" if secret_info.get("rotation_enabled") else "❌ Disabled"
        )
        encryption = "🔐 KMS" if secret_info.get("kms_key_id") else "🔓 Default"

        # Security status
        security_status = []
        if secret_info.get("rotation_enabled"):
            security_status.append("[green]✓[/green] Rotation")
        else:
            security_status.append("[red]✗[/red] Rotation")

        if secret_info.get("kms_key_id"):
            security_status.append("[green]✓[/green] Custom KMS")
        else:
            security_status.append("[yellow]⚠[/yellow] Default KMS")

        panel_content = (
            f"[bold]ARN:[/bold] {secret_info.get('arn', 'N/A')}\n"
            f"[bold]Description:[/bold] {secret_info.get('description', 'N/A')}\n\n"
            f"[bold cyan]Security:[/bold cyan]\n"
            f"  Rotation: {rotation_status}\n"
            f"  Encryption: {encryption}\n"
            f"  Status: {' | '.join(security_status)}\n\n"
        )

        if secret_info.get("rotation_enabled"):
            rotation_rules = secret_info.get("rotation_rules", {})
            panel_content += (
                f"[bold cyan]Rotation:[/bold cyan]\n"
                f"  Lambda ARN: {secret_info.get('rotation_lambda_arn', 'N/A')}\n"
                f"  Automatically After Days: {rotation_rules.get('AutomaticallyAfterDays', 'N/A')}\n"
                f"  Last Rotated: {secret_info.get('last_rotated_date', 'Never')}\n\n"
            )

        panel_content += (
            f"[bold cyan]Timestamps:[/bold cyan]\n"
            f"  Created: {secret_info.get('created_date', 'N/A')}\n"
            f"  Last Changed: {secret_info.get('last_changed_date', 'N/A')}\n"
            f"  Last Accessed: {secret_info.get('last_accessed_date', 'N/A')}\n"
        )

        if secret_info.get("tags"):
            tags_str = ", ".join(
                [
                    f"{t.get('Key')}={t.get('Value')}"
                    for t in secret_info.get("tags", [])
                ]
            )
            panel_content += f"\n[bold cyan]Tags:[/bold cyan] {tags_str}"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{secret_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def _check_secret_security(self, secret_info: Dict[str, Any]) -> List[str]:
        """Check secret for security issues"""
        findings = []
        secret_name = secret_info.get("name")

        if not secret_info.get("rotation_enabled"):
            findings.append(f"Secret '{secret_name}' does not have rotation enabled")

        if not secret_info.get("kms_key_id"):
            findings.append(
                f"Secret '{secret_name}' uses default KMS key instead of customer-managed key"
            )

        if not secret_info.get("last_accessed_date"):
            findings.append(f"Secret '{secret_name}' has never been accessed")

        # Check if secret is old and never rotated
        if secret_info.get("created_date") and not secret_info.get("last_rotated_date"):
            findings.append(
                f"Secret '{secret_name}' has never been rotated since creation"
            )

        return findings

    def enumerate_parameters(self):
        """Enumerate all SSM Parameter Store parameters"""
        if not self.options.get("ENUMERATE_PARAMETERS"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Parameter Store Parameters ═══[/bold cyan]"
        )

        try:
            paginator = self.ssm_client.get_paginator("describe_parameters")
            parameter_count = 0

            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    parameter_count += 1
                    param_name = param.get("Name", "")

                    console.print(
                        f"\n[cyan]Parameter {parameter_count}:[/cyan] {param_name}"
                    )

                    # Get parameter details
                    param_info = self._get_parameter_details(param_name, param)
                    self.data["parameters"].append(param_info)

                    # Track encrypted parameters
                    if param_info.get("type") == "SecureString":
                        self.data["encrypted_parameters"].append(param_name)

                    # Display parameter panel
                    self._display_parameter_panel(param_info)

            self.data["total_parameters"] = parameter_count
            console.print(f"\n[green]✓[/green] Found {parameter_count} parameters")

        except ClientError as e:
            console.print(
                f"[red]✗[/red] Error enumerating parameters: {e.response['Error']['Message']}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _get_parameter_details(
        self, param_name: str, param_metadata: Dict
    ) -> Dict[str, Any]:
        """Get detailed information about a parameter"""
        try:
            param_info = {
                "name": param_name,
                "type": param_metadata.get("Type", ""),
                "key_id": param_metadata.get("KeyId", ""),
                "last_modified_date": str(param_metadata.get("LastModifiedDate", ""))
                if param_metadata.get("LastModifiedDate")
                else "",
                "last_modified_user": param_metadata.get("LastModifiedUser", ""),
                "description": param_metadata.get("Description", ""),
                "version": param_metadata.get("Version", 0),
                "tier": param_metadata.get("Tier", "Standard"),
                "policies": param_metadata.get("Policies", []),
                "data_type": param_metadata.get("DataType", "text"),
            }

            # Get tags
            try:
                tags_response = self.ssm_client.list_tags_for_resource(
                    ResourceType="Parameter", ResourceId=param_name
                )
                param_info["tags"] = tags_response.get("TagList", [])
            except ClientError:
                param_info["tags"] = []

            # Optionally retrieve parameter value
            if self.options.get("RETRIEVE_VALUES"):
                try:
                    value_response = self.ssm_client.get_parameter(
                        Name=param_name, WithDecryption=True
                    )
                    param_info["value"] = value_response.get("Parameter", {}).get(
                        "Value", ""
                    )
                except ClientError as e:
                    param_info["value_error"] = str(e)

            return param_info

        except Exception as e:
            return {"name": param_name, "error": str(e)}

    def _display_parameter_panel(self, param_info: Dict[str, Any]):
        """Display parameter information in a formatted panel"""
        param_type = param_info.get("type", "String")
        encryption = "🔐 Encrypted" if param_type == "SecureString" else "🔓 Plain"

        panel_content = (
            f"[bold]Name:[/bold] {param_info.get('name', 'N/A')}\n"
            f"[bold]Type:[/bold] {param_type} ({encryption})\n"
            f"[bold]Tier:[/bold] {param_info.get('tier', 'Standard')}\n"
            f"[bold]Version:[/bold] {param_info.get('version', 0)}\n\n"
        )

        if param_info.get("description"):
            panel_content += (
                f"[bold]Description:[/bold] {param_info.get('description')}\n\n"
            )

        if param_type == "SecureString" and param_info.get("key_id"):
            panel_content += f"[bold cyan]Encryption:[/bold cyan]\n  KMS Key: {param_info.get('key_id')}\n\n"

        panel_content += (
            f"[bold cyan]Metadata:[/bold cyan]\n"
            f"  Last Modified: {param_info.get('last_modified_date', 'N/A')}\n"
            f"  Modified By: {param_info.get('last_modified_user', 'N/A')}\n"
            f"  Data Type: {param_info.get('data_type', 'text')}\n"
        )

        if param_info.get("tags"):
            tags_str = ", ".join(
                [f"{t.get('Key')}={t.get('Value')}" for t in param_info.get("tags", [])]
            )
            panel_content += f"\n[bold cyan]Tags:[/bold cyan] {tags_str}"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{param_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"secrets_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            result_data = {
                "metadata": {
                    "scan_date": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "module": self.NAME,
                    "version": self.VERSION,
                },
                "summary": {
                    "total_secrets": self.data["total_secrets"],
                    "total_parameters": self.data["total_parameters"],
                    "secrets_with_rotation": len(self.data["secrets_with_rotation"]),
                    "secrets_without_rotation": len(
                        self.data["secrets_without_rotation"]
                    ),
                    "encrypted_parameters": len(self.data["encrypted_parameters"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "secrets": self.data["secrets"],
                "parameters": self.data["parameters"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(result_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute Secrets Manager and Parameter Store enumeration"""

        panel = Panel(
            "[bold cyan]AWS Secrets Manager & Parameter Store Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting secrets, parameters, rotation configs, and security settings[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize clients
        if not self.initialize_client():
            return {
                "success": False,
                "status": "failed",
                "message": "Failed to initialize AWS clients",
            }

        # Execute enumeration
        self.enumerate_secrets()
        self.enumerate_parameters()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]Secrets Manager:[/bold] {self.data['total_secrets']} secrets | "
            f"[green]✓[/green] Rotation: {len(self.data['secrets_with_rotation'])} | "
            f"[red]✗[/red] No Rotation: {len(self.data['secrets_without_rotation'])}"
        )
        console.print(
            f"[bold]Parameter Store:[/bold] {self.data['total_parameters']} parameters | "
            f"[green]🔐[/green] Encrypted: {len(self.data['encrypted_parameters'])}"
        )

        if self.data["security_findings"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Security Findings: {len(self.data['security_findings'])}"
            )
            for finding in self.data["security_findings"][:5]:  # Show first 5
                console.print(f"  • {finding}")
            if len(self.data["security_findings"]) > 5:
                console.print(
                    f"  ... and {len(self.data['security_findings']) - 5} more"
                )

        return {
            "success": True,
            "status": "completed",
            "message": f"Enumeration complete. Results saved to {output_file}",
            "output_file": output_file,
            "summary": {
                "secrets": {
                    "total": self.data["total_secrets"],
                    "with_rotation": len(self.data["secrets_with_rotation"]),
                    "without_rotation": len(self.data["secrets_without_rotation"]),
                },
                "parameters": {
                    "total": self.data["total_parameters"],
                    "encrypted": len(self.data["encrypted_parameters"]),
                },
                "security_findings": len(self.data["security_findings"]),
            },
        }
