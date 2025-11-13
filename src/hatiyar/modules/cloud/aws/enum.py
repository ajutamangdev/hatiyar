"""AWS Cloud Enumeration Module - Orchestrator

This module orchestrates comprehensive AWS cloud enumeration by leveraging
specialized resource modules for EC2, S3, IAM, Lambda, Databases, Containers, Route53, Amplify, and Secrets.
"""

from typing import Dict, Any
import importlib
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from hatiyar.core.module_base import ModuleBase, ModuleType
from hatiyar.utils.output import save_json_results

console = Console()

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

# Import specialized resource modules
try:
    from . import ec2
    from . import s3
    from . import iam

    # Lambda is a reserved keyword, use importlib
    lambda_module: Any = importlib.import_module(
        ".lambda", package="hatiyar.modules.cloud.aws"
    )
    from . import database
    from . import container
    from . import route53
    from . import amplify
    from . import secrets

    SPECIALIZED_MODULES_AVAILABLE = True
except ImportError as e:
    SPECIALIZED_MODULES_AVAILABLE = False
    lambda_module = None  # type: ignore
    console.print(f"[yellow]⚠ Warning: Could not import all AWS modules: {e}[/yellow]")


class Module(ModuleBase):
    """AWS cloud enumeration orchestrator - leverages specialized resource modules."""

    NAME = "aws_enumeration"
    DESCRIPTION = "Comprehensive AWS cloud enumeration orchestrator using specialized resource modules"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",  # AWS CLI profile to use
        "ACCESS_KEY": "",  # AWS Access Key ID
        "SECRET_KEY": "",  # AWS Secret Access Key
        "SESSION_TOKEN": "",  # Optional session token for temporary credentials
        "ALL_REGIONS": True,  # Enumerate across all AWS regions
        "ENUMERATE_EC2": True,
        "ENUMERATE_S3": True,
        "ENUMERATE_IAM": True,
        "ENUMERATE_LAMBDA": True,
        "ENUMERATE_DATABASES": True,
        "ENUMERATE_CONTAINERS": True,
        "ENUMERATE_ROUTE53": True,
        "ENUMERATE_AMPLIFY": True,
        "ENUMERATE_SECRETS": True,
        "OUTPUT_FILE": "aws_enumeration_results.json",
    }

    REQUIRED_OPTIONS = []

    def __init__(self):
        super().__init__()
        self.session = None
        self.account_id = None
        self.available_regions = []
        self.data = {
            "account_info": {},
            "regions": {},  # Will store per-region data
            "global_services": {},  # IAM, Route53, S3 (global services)
            "security_findings": [],
            "region_summary": {},
        }

    def initialize_session(self) -> bool:
        """Initialize AWS session"""
        if not BOTO3_AVAILABLE:
            console.print("[red]✗[/red] Boto3 not installed.")
            console.print("[yellow]Install with:[/yellow] pip install boto3")
            return False

        try:
            session_kwargs = {
                "region_name": self.options.get("AWS_REGION", "us-east-1")
            }

            if self.options.get("AWS_PROFILE"):
                session_kwargs["profile_name"] = self.options["AWS_PROFILE"]
                console.print(
                    f"[cyan]→[/cyan] Using AWS profile: {self.options['AWS_PROFILE']}"
                )
            elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
                session_kwargs["aws_access_key_id"] = self.options["ACCESS_KEY"]
                session_kwargs["aws_secret_access_key"] = self.options["SECRET_KEY"]
                if self.options.get("SESSION_TOKEN"):
                    session_kwargs["aws_session_token"] = self.options["SESSION_TOKEN"]
                console.print("[cyan]→[/cyan] Using provided credentials")
            else:
                console.print("[cyan]→[/cyan] Using default AWS credentials")

            self.session = boto3.Session(**session_kwargs)  # type: ignore

            # Test connection and get account info
            sts_client = self.session.client("sts")  # type: ignore
            identity = sts_client.get_caller_identity()
            self.account_id = identity["Account"]

            console.print(
                f"[green]✓[/green] Connected to AWS Account: {self.account_id}"
            )

            # Get available regions
            self._get_available_regions()

            return True

        except NoCredentialsError:  # type: ignore
            console.print("[red]✗[/red] No AWS credentials found")
            console.print(
                "[yellow]Hint:[/yellow] Configure AWS credentials or set ACCESS_KEY/SECRET_KEY options"
            )
            return False
        except ClientError as e:  # type: ignore
            console.print(f"[red]✗[/red] AWS API error: {str(e)}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")
            return False

    def _get_available_regions(self):
        """Get all available AWS regions"""
        try:
            if self.options.get("ALL_REGIONS"):
                ec2_client = self.session.client("ec2")  # type: ignore
                response = ec2_client.describe_regions(AllRegions=False)
                self.available_regions = [
                    region["RegionName"] for region in response["Regions"]
                ]
                console.print(
                    f"[cyan]→[/cyan] Found {len(self.available_regions)} available regions"
                )
                console.print(
                    f"[dim]Regions: {', '.join(self.available_regions[:5])}{'...' if len(self.available_regions) > 5 else ''}[/dim]"
                )
            else:
                # Use single region
                self.available_regions = [self.options.get("AWS_REGION", "us-east-1")]
                console.print(
                    f"[cyan]→[/cyan] Using single region: {self.available_regions[0]}"
                )
        except Exception as e:
            console.print(
                f"[yellow]![/yellow] Could not get available regions: {str(e)}"
            )
            console.print("[yellow]→[/yellow] Falling back to single region")
            self.available_regions = [self.options.get("AWS_REGION", "us-east-1")]

    def run(self) -> Dict[str, Any]:
        """Execute comprehensive AWS enumeration using specialized resource modules"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        if not self.initialize_session():
            return {"success": False, "error": "Failed to connect to AWS"}

        panel = Panel(
            "[bold cyan]Starting Comprehensive AWS Cloud Enumeration[/bold cyan]\n"
            f"Account: {self.account_id}\n"
            f"Regions: {len(self.available_regions)} ({'all' if self.options.get('ALL_REGIONS') else 'single'})\n"
            "[dim]Orchestrating specialized resource modules across all regions...[/dim]",
            expand=False,
        )
        console.print(panel)

        # Get account info
        self._get_account_info()

        if not SPECIALIZED_MODULES_AVAILABLE:
            console.print("[yellow]⚠ Specialized modules not available[/yellow]")
            return {"success": False, "error": "Specialized modules not found"}

        # Enumerate global services first (only once, not per-region)
        console.print(
            "\n[bold magenta]═══ Global Services (Region-Independent) ═══[/bold magenta]"
        )
        self._enumerate_global_services()

        # Enumerate regional services across all regions
        console.print("\n[bold cyan]═══ Regional Services Enumeration ═══[/bold cyan]")
        total_regions = len(self.available_regions)

        for idx, region in enumerate(self.available_regions, 1):
            console.print(
                f"\n[bold yellow]→ Region {idx}/{total_regions}: {region}[/bold yellow]"
            )
            self._enumerate_region(region)

        # Aggregate security findings
        self._aggregate_security_findings()

        # Generate region summary
        self._generate_region_summary()

        # Display and save results
        self._display_results()
        self._save_results()

        return {
            "success": True,
            # "data": self.data,
            "output_file": self.options.get("OUTPUT_FILE"),
            "regions_scanned": len(self.available_regions),
        }

    def _enumerate_global_services(self):
        """Enumerate AWS global services (IAM, Route53, S3)"""
        # These services are global and only need to be enumerated once
        common_options = {
            "AWS_REGION": "us-east-1",  # Global services use us-east-1
            "AWS_PROFILE": self.options.get("AWS_PROFILE"),
            "ACCESS_KEY": self.options.get("ACCESS_KEY"),
            "SECRET_KEY": self.options.get("SECRET_KEY"),
            "SESSION_TOKEN": self.options.get("SESSION_TOKEN"),
        }

        self.data["global_services"] = {}

        # S3 (global service)
        if self.options.get("ENUMERATE_S3"):
            self._use_s3_module(common_options)
            self.data["global_services"]["s3"] = self.data.pop("s3", {})

        # IAM (global service)
        if self.options.get("ENUMERATE_IAM"):
            self._use_iam_module(common_options)
            self.data["global_services"]["iam"] = self.data.pop("iam", {})

        # Route53 (global service)
        if self.options.get("ENUMERATE_ROUTE53"):
            self._use_route53_module(common_options)
            self.data["global_services"]["route53"] = self.data.pop("route53", {})

    def _enumerate_region(self, region: str):
        """Enumerate AWS resources in a specific region"""
        # Common options for this region
        common_options = {
            "AWS_REGION": region,
            "AWS_PROFILE": self.options.get("AWS_PROFILE"),
            "ACCESS_KEY": self.options.get("ACCESS_KEY"),
            "SECRET_KEY": self.options.get("SECRET_KEY"),
            "SESSION_TOKEN": self.options.get("SESSION_TOKEN"),
        }

        # Initialize region data
        self.data["regions"][region] = {}

        # EC2 Enumeration
        if self.options.get("ENUMERATE_EC2"):
            self._use_ec2_module(common_options)
            self.data["regions"][region]["ec2"] = self.data.pop("ec2", {})

        # Lambda Enumeration
        if self.options.get("ENUMERATE_LAMBDA"):
            self._use_lambda_module(common_options)
            self.data["regions"][region]["lambda"] = self.data.pop("lambda", {})

        # Database Enumeration
        if self.options.get("ENUMERATE_DATABASES"):
            self._use_database_module(common_options)
            self.data["regions"][region]["databases"] = self.data.pop("databases", {})

        # Container Enumeration
        if self.options.get("ENUMERATE_CONTAINERS"):
            self._use_container_module(common_options)
            self.data["regions"][region]["containers"] = self.data.pop("containers", {})

        # Amplify Enumeration
        if self.options.get("ENUMERATE_AMPLIFY"):
            self._use_amplify_module(common_options)
            self.data["regions"][region]["amplify"] = self.data.pop("amplify", {})

        # Secrets Enumeration
        if self.options.get("ENUMERATE_SECRETS"):
            self._use_secrets_module(common_options)
            self.data["regions"][region]["secrets"] = self.data.pop("secrets", {})

    def _generate_region_summary(self):
        """Generate summary of resources across all regions"""
        console.print("\n[cyan]→[/cyan] Generating cross-region summary...")

        summary = {
            "total_regions": len(self.available_regions),
            "regions_with_resources": 0,
            "total_resources_by_service": {
                "ec2_instances": 0,
                "lambda_functions": 0,
                "databases": 0,
                "containers": 0,
                "amplify_apps": 0,
                "secrets": 0,
            },
            "regions_by_resource_count": [],
        }

        for region, data in self.data["regions"].items():
            region_resource_count = 0

            # Count EC2 instances
            if "ec2" in data and data["ec2"].get("compute"):
                instances = data["ec2"]["compute"].get("total_instances", 0)
                summary["total_resources_by_service"]["ec2_instances"] += instances
                region_resource_count += instances

            # Count Lambda functions
            if "lambda" in data:
                functions = data["lambda"].get("total_functions", 0)
                summary["total_resources_by_service"]["lambda_functions"] += functions
                region_resource_count += functions

            # Count Databases
            if "databases" in data:
                dbs = data["databases"].get("total_rds_instances", 0) + data[
                    "databases"
                ].get("total_dynamodb_tables", 0)
                summary["total_resources_by_service"]["databases"] += dbs
                region_resource_count += dbs

            # Count Containers
            if "containers" in data:
                containers = data["containers"].get("total_ecs_clusters", 0) + data[
                    "containers"
                ].get("total_eks_clusters", 0)
                summary["total_resources_by_service"]["containers"] += containers
                region_resource_count += containers

            # Count Amplify apps
            if "amplify" in data:
                apps = data["amplify"].get("total_apps", 0)
                summary["total_resources_by_service"]["amplify_apps"] += apps
                region_resource_count += apps

            # Count Secrets
            if "secrets" in data:
                secrets_count = data["secrets"].get("total_secrets", 0) + data[
                    "secrets"
                ].get("total_parameters", 0)
                summary["total_resources_by_service"]["secrets"] += secrets_count
                region_resource_count += secrets_count

            if region_resource_count > 0:
                summary["regions_with_resources"] += 1
                summary["regions_by_resource_count"].append(
                    {
                        "region": region,
                        "resource_count": region_resource_count,
                    }
                )

        # Sort regions by resource count
        summary["regions_by_resource_count"].sort(
            key=lambda x: x["resource_count"], reverse=True
        )

        self.data["region_summary"] = summary
        console.print(
            f"[green]✓[/green] Found resources in {summary['regions_with_resources']}/{summary['total_regions']} regions"
        )

    def _get_account_info(self):
        """Get AWS account information"""
        try:
            console.print("[cyan]→[/cyan] Getting account information...")
            sts_client = self.session.client("sts")  # type: ignore
            identity = sts_client.get_caller_identity()

            # Get organizations info if available
            org_info = None
            try:
                org_client = self.session.client("organizations")  # type: ignore
                org_info = org_client.describe_organization()["Organization"]
            except Exception:
                pass

            self.data["account_info"] = {
                "account_id": identity["Account"],
                "user_arn": identity["Arn"],
                "user_id": identity["UserId"],
                "regions_enumerated": self.available_regions,
                "total_regions": len(self.available_regions),
                "all_regions_enabled": self.options.get("ALL_REGIONS", False),
                "enumeration_time": datetime.now().isoformat(),
                "organization": org_info.get("Id") if org_info else None,
            }

            console.print(f"[green]✓[/green] Account: {identity['Account']}")
        except Exception as e:
            console.print(f"[yellow]![/yellow] Could not get account info: {str(e)}")

    def _use_ec2_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized EC2 module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]EC2 & VPC Enumeration[/bold]")
            ec2_mod = ec2.Module()  # type: ignore

            # Configure module options
            for key, value in common_options.items():
                ec2_mod.options[key] = value
            ec2_mod.options["ENUMERATE_INSTANCES"] = True
            ec2_mod.options["OUTPUT_FILE"] = "ec2_temp.json"

            result = ec2_mod.run()

            if result.get("success"):
                self.data["ec2"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] EC2 enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] EC2 module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using EC2 module: {str(e)}")

    def _use_s3_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized S3 module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]S3 Storage Enumeration[/bold]")
            s3_mod = s3.Module()  # type: ignore

            for key, value in common_options.items():
                s3_mod.options[key] = value
            s3_mod.options["OUTPUT_FILE"] = "s3_temp.json"

            result = s3_mod.run()

            if result.get("success"):
                self.data["s3"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] S3 enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] S3 module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using S3 module: {str(e)}")

    def _use_iam_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized IAM module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]IAM Security Enumeration[/bold]")
            iam_mod = iam.Module()  # type: ignore

            for key, value in common_options.items():
                iam_mod.options[key] = value
            iam_mod.options["OUTPUT_FILE"] = "iam_temp.json"

            result = iam_mod.run()

            if result.get("success"):
                self.data["iam"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] IAM enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] IAM module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using IAM module: {str(e)}")

    def _use_lambda_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Lambda module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]Lambda Functions Enumeration[/bold]")
            if lambda_module is None:
                console.print("[yellow]![/yellow] Lambda module not available")
                return
            lambda_mod = lambda_module.Module()  # type: ignore

            for key, value in common_options.items():
                lambda_mod.options[key] = value
            lambda_mod.options["OUTPUT_FILE"] = "lambda_temp.json"

            result = lambda_mod.run()

            if result.get("success"):
                self.data["lambda"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Lambda enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yeah]![/yellow] Lambda module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Lambda module: {str(e)}")

    def _use_database_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Database module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]Database Services Enumeration[/bold]")
            db_mod = database.Module()  # type: ignore

            for key, value in common_options.items():
                db_mod.options[key] = value
            db_mod.options["OUTPUT_FILE"] = "database_temp.json"

            result = db_mod.run()

            if result.get("success"):
                self.data["databases"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Database enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] Database module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Database module: {str(e)}")

    def _use_container_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Container module for enumeration"""
        try:
            console.print(
                "\n[cyan]→[/cyan] [bold]Container Services Enumeration[/bold]"
            )
            container_mod = container.Module()  # type: ignore

            for key, value in common_options.items():
                container_mod.options[key] = value
            container_mod.options["OUTPUT_FILE"] = "container_temp.json"

            result = container_mod.run()

            if result.get("success"):
                self.data["containers"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Container enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] Container module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Container module: {str(e)}")

    def _use_route53_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Route53 module for enumeration"""
        try:
            console.print("\n[cyan]→[/cyan] [bold]Route53 DNS Enumeration[/bold]")
            route53_mod = route53.Module()  # type: ignore

            for key, value in common_options.items():
                route53_mod.options[key] = value
            route53_mod.options["OUTPUT_FILE"] = "route53_temp.json"

            result = route53_mod.run()

            if result.get("success"):
                self.data["route53"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Route53 enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] Route53 module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Route53 module: {str(e)}")

    def _use_amplify_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Amplify module for enumeration"""
        try:
            console.print(
                "\n[cyan]→[/cyan] [bold]Amplify Applications Enumeration[/bold]"
            )
            amplify_mod = amplify.Module()  # type: ignore

            for key, value in common_options.items():
                amplify_mod.options[key] = value
            amplify_mod.options["OUTPUT_FILE"] = "amplify_temp.json"

            result = amplify_mod.run()

            if result.get("success"):
                self.data["amplify"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Amplify enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] Amplify module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Amplify module: {str(e)}")

    def _use_secrets_module(self, common_options: Dict[str, Any]):  # type: ignore
        """Use specialized Secrets module for enumeration"""
        try:
            console.print(
                "\n[cyan]→[/cyan] [bold]Secrets Manager & Parameter Store Enumeration[/bold]"
            )
            secrets_mod = secrets.Module()  # type: ignore

            for key, value in common_options.items():
                secrets_mod.options[key] = value
            secrets_mod.options["OUTPUT_FILE"] = "secrets_temp.json"

            result = secrets_mod.run()

            if result.get("success"):
                self.data["secrets"] = result.get("summary", {})
                console.print(
                    "[green]✓[/green] Secrets enumeration complete (via specialized module)"
                )
            else:
                console.print(
                    f"[yellow]![/yellow] Secrets module returned error: {result.get('error', 'Unknown')}"
                )
        except Exception as e:
            console.print(f"[red]✗[/red] Error using Secrets module: {str(e)}")

    def _aggregate_security_findings(self):
        """Aggregate security findings from all modules across all regions"""
        console.print(
            "\n[bold yellow]Aggregating Security Findings Across All Regions[/bold yellow]"
        )

        findings_count = 0

        # Aggregate from global services
        global_services = self.data.get("global_services", {})

        # S3 Security Checks (global)
        if "s3" in global_services:
            s3_data = global_services["s3"]
            if s3_data.get("security"):
                findings = s3_data["security"]
                if findings.get("public_buckets"):
                    findings_count += 1
                    self.data["security_findings"].append(
                        {
                            "severity": "HIGH",
                            "service": "S3",
                            "region": "Global",
                            "finding": "Publicly Accessible Buckets",
                            "count": findings["public_buckets"],
                        }
                    )
                if findings.get("unencrypted_buckets"):
                    findings_count += 1
                    self.data["security_findings"].append(
                        {
                            "severity": "MEDIUM",
                            "service": "S3",
                            "region": "Global",
                            "finding": "Unencrypted Buckets",
                            "count": findings["unencrypted_buckets"],
                        }
                    )

        # IAM Security Checks (global)
        if "iam" in global_services:
            iam_data = global_services["iam"]
            if iam_data.get("security"):
                findings = iam_data["security"]
                if findings.get("users_without_mfa"):
                    findings_count += 1
                    self.data["security_findings"].append(
                        {
                            "severity": "HIGH",
                            "service": "IAM",
                            "region": "Global",
                            "finding": "Users Without MFA",
                            "count": findings["users_without_mfa"],
                        }
                    )
                if findings.get("access_keys_not_rotated"):
                    findings_count += 1
                    self.data["security_findings"].append(
                        {
                            "severity": "MEDIUM",
                            "service": "IAM",
                            "region": "Global",
                            "finding": "Access Keys Not Rotated (>90 days)",
                            "count": findings["access_keys_not_rotated"],
                        }
                    )

        # Aggregate from regional services
        for region, region_data in self.data.get("regions", {}).items():
            # EC2 Security Checks
            if "ec2" in region_data:
                ec2_data = region_data["ec2"]
                if ec2_data.get("security"):
                    findings = ec2_data["security"]
                    if findings.get("public_instances"):
                        findings_count += 1
                        self.data["security_findings"].append(
                            {
                                "severity": "MEDIUM",
                                "service": "EC2",
                                "region": region,
                                "finding": "Public EC2 Instances",
                                "count": findings["public_instances"],
                            }
                        )
                    if findings.get("unrestricted_security_groups"):
                        findings_count += 1
                        self.data["security_findings"].append(
                            {
                                "severity": "HIGH",
                                "service": "EC2",
                                "region": region,
                                "finding": "Unrestricted Security Groups (0.0.0.0/0)",
                                "count": findings["unrestricted_security_groups"],
                            }
                        )

        console.print(
            f"[green]✓[/green] Aggregated {findings_count} security findings across all regions"
        )

    def _display_results(self):
        """Display enumeration results"""
        console.print(
            "\n[bold green]═══ AWS Multi-Region Enumeration Results ═══[/bold green]\n"
        )

        # Region Summary
        region_summary = self.data.get("region_summary", {})
        if region_summary:
            console.print(
                f"[bold cyan]Regions Scanned:[/bold cyan] {region_summary['total_regions']}"
            )
            console.print(
                f"[bold cyan]Regions with Resources:[/bold cyan] {region_summary['regions_with_resources']}\n"
            )

            # Top regions by resource count
            if region_summary["regions_by_resource_count"]:
                console.print("[bold]Top 5 Regions by Resource Count:[/bold]")
                for entry in region_summary["regions_by_resource_count"][:5]:
                    console.print(
                        f"  • {entry['region']}: {entry['resource_count']} resources"
                    )
                console.print("")

        # Global Services Summary
        global_services = self.data.get("global_services", {})
        if global_services:
            console.print("[bold magenta]Global Services:[/bold magenta]")

            if "s3" in global_services:
                s3_data = global_services["s3"]
                console.print(f"  • S3: {s3_data.get('total_buckets', 0)} buckets")

            if "iam" in global_services:
                iam_data = global_services["iam"]
                console.print(
                    f"  • IAM: {iam_data.get('total_users', 0)} users, {iam_data.get('total_roles', 0)} roles"
                )

            if "route53" in global_services:
                route53_data = global_services["route53"]
                console.print(
                    f"  • Route53: {route53_data.get('total_hosted_zones', 0)} hosted zones"
                )

            console.print("")

        # Cross-region totals
        totals = region_summary.get("total_resources_by_service", {})
        if totals:
            totals_table = Table(
                title="Cross-Region Resource Totals",
                show_header=True,
                header_style="bold cyan",
            )
            totals_table.add_column("Service", style="cyan")
            totals_table.add_column("Total Resources", justify="right", style="green")

            if totals.get("ec2_instances"):
                totals_table.add_row("EC2 Instances", str(totals["ec2_instances"]))
            if totals.get("lambda_functions"):
                totals_table.add_row(
                    "Lambda Functions", str(totals["lambda_functions"])
                )
            if totals.get("databases"):
                totals_table.add_row("Databases", str(totals["databases"]))
            if totals.get("containers"):
                totals_table.add_row("Container Clusters", str(totals["containers"]))
            if totals.get("amplify_apps"):
                totals_table.add_row("Amplify Apps", str(totals["amplify_apps"]))
            if totals.get("secrets"):
                totals_table.add_row("Secrets/Parameters", str(totals["secrets"]))

            console.print(totals_table)

        # Security findings
        if self.data["security_findings"]:
            console.print(
                "\n[bold yellow]Security Findings Across All Regions[/bold yellow]\n"
            )

            # Group by severity
            high_findings = [
                f for f in self.data["security_findings"] if f["severity"] == "HIGH"
            ]
            medium_findings = [
                f for f in self.data["security_findings"] if f["severity"] == "MEDIUM"
            ]

            if high_findings:
                console.print("[bold red]HIGH Severity:[/bold red]")
                for finding in high_findings:
                    console.print(
                        f"  [red]●[/red] [{finding['service']}] {finding['finding']} "
                        f"in {finding['region']}: {finding['count']}"
                    )

            if medium_findings:
                console.print("\n[bold yellow]MEDIUM Severity:[/bold yellow]")
                for finding in medium_findings:
                    console.print(
                        f"  [yellow]●[/yellow] [{finding['service']}] {finding['finding']} "
                        f"in {finding['region']}: {finding['count']}"
                    )

            console.print(
                f"\n[bold]Total Findings:[/bold] {len(self.data['security_findings'])}"
            )

    def _save_results(self):
        """Save results to JSON file"""
        try:
            output_file = self.options.get(
                "OUTPUT_FILE", "aws_enumeration_results.json"
            )
            output_path = Path(output_file).expanduser()
            save_json_results(self.data, output_path)
            console.print(
                f"\n[green]✓[/green] Results saved to: {output_path.absolute()}"
            )
        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
