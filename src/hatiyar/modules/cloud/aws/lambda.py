"""AWS Lambda Enumeration Module"""

from typing import Dict, Any, List
import json
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
    """AWS Lambda enumeration including functions, layers, event sources, and security analysis."""

    NAME = "lambda_enumeration"
    DESCRIPTION = "AWS Lambda function and configuration enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_LAYERS": True,
        "ENUMERATE_EVENT_SOURCES": True,
        "CHECK_DEPRECATED_RUNTIMES": True,
        "OUTPUT_FILE": "lambda_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.lambda_client = None
        self.iam_client = None
        self.data = {
            "functions": [],
            "layers": [],
            "event_source_mappings": [],
            "security_findings": [],
            "total_functions": 0,
            "total_layers": 0,
            "deprecated_runtimes": [],
            "vpc_functions": [],
            "functions_with_dlq": [],
        }
        self.deprecated_runtimes = [
            "python2.7",
            "python3.6",
            "python3.7",
            "nodejs10.x",
            "nodejs12.x",
            "nodejs14.x",
            "ruby2.5",
            "ruby2.7",
            "dotnetcore2.1",
            "dotnetcore3.1",
            "java8",
            "go1.x",
        ]

    def _get_session_kwargs(self) -> Dict[str, Any]:
        """Build AWS session configuration from options."""
        kwargs: Dict[str, Any] = {"region_name": self.options.get("AWS_REGION")}

        if self.options.get("AWS_PROFILE"):
            kwargs["profile_name"] = self.options.get("AWS_PROFILE")
        elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
            kwargs["aws_access_key_id"] = self.options.get("ACCESS_KEY")
            kwargs["aws_secret_access_key"] = self.options.get("SECRET_KEY")
            if self.options.get("SESSION_TOKEN"):
                kwargs["aws_session_token"] = self.options.get("SESSION_TOKEN")

        return kwargs

    def initialize_client(self) -> bool:
        """Initialize AWS Lambda client."""
        try:
            session_kwargs = self._get_session_kwargs()

            session = boto3.Session(**session_kwargs)
            self.lambda_client = session.client("lambda")
            self.iam_client = session.client("iam")

            # Test connection
            self.lambda_client.list_functions(MaxItems=1)
            console.print("[green]✓[/green] Successfully connected to AWS Lambda")
            return True

        except NoCredentialsError:
            console.print(
                "[red]✗[/red] No AWS credentials found. Please configure:\n"
                "  - AWS_PROFILE option, or\n"
                "  - ACCESS_KEY and SECRET_KEY options, or\n"
                "  - Default AWS credentials (~/.aws/credentials)"
            )
            return False
        except PartialCredentialsError:
            console.print("[red]✗[/red] Incomplete AWS credentials provided")
            return False
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] AWS API Error ({error_code}): {error_msg}\n"
                "[dim]Check your credentials and permissions[/dim]"
            )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize Lambda client: {str(e)}")
            return False

    def _get_function_configuration(self, function_name: str) -> Dict[str, Any]:
        """Get detailed function configuration"""
        try:
            config = self.lambda_client.get_function_configuration(
                FunctionName=function_name
            )

            # Get function URL if exists
            function_urls = []
            try:
                url_config = self.lambda_client.get_function_url_config(
                    FunctionName=function_name
                )
                function_urls.append(url_config.get("FunctionUrl"))
            except ClientError:
                pass

            # Get policy
            policy = None
            try:
                policy_response = self.lambda_client.get_policy(
                    FunctionName=function_name
                )
                policy = json.loads(policy_response.get("Policy", "{}"))
            except ClientError:
                pass

            # Get aliases
            aliases = []
            try:
                alias_response = self.lambda_client.list_aliases(
                    FunctionName=function_name
                )
                aliases = alias_response.get("Aliases", [])
            except ClientError:
                pass

            # Get tags
            tags = []
            try:
                tag_response = self.lambda_client.list_tags(
                    Resource=config.get("FunctionArn")
                )
                tags = [
                    {"Key": k, "Value": v}
                    for k, v in tag_response.get("Tags", {}).items()
                ]
            except ClientError:
                pass

            return {
                "name": config.get("FunctionName"),
                "arn": config.get("FunctionArn"),
                "runtime": config.get("Runtime"),
                "handler": config.get("Handler"),
                "code_size": config.get("CodeSize"),
                "description": config.get("Description", ""),
                "timeout": config.get("Timeout"),
                "memory_size": config.get("MemorySize"),
                "last_modified": config.get("LastModified"),
                "role": config.get("Role"),
                "environment": config.get("Environment", {}).get("Variables", {}),
                "vpc_config": config.get("VpcConfig"),
                "layers": config.get("Layers", []),
                "dead_letter_config": config.get("DeadLetterConfig"),
                "tracing_config": config.get("TracingConfig"),
                "architectures": config.get("Architectures", []),
                "package_type": config.get("PackageType", "Zip"),
                "state": config.get("State"),
                "state_reason": config.get("StateReason", ""),
                "reserved_concurrent_executions": config.get(
                    "ReservedConcurrentExecutions"
                ),
                "function_urls": function_urls,
                "policy": policy,
                "aliases": aliases,
                "tags": tags,
            }

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error getting configuration for {function_name}: {str(e)}"
            )
            return {}

    def _get_event_source_mappings(self, function_name: str) -> List[Dict[str, Any]]:
        """Get event source mappings for a function"""
        try:
            response = self.lambda_client.list_event_source_mappings(
                FunctionName=function_name
            )
            return response.get("EventSourceMappings", [])
        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error getting event sources for {function_name}: {str(e)}"
            )
            return []

    def enumerate_functions(self):
        """Enumerate all Lambda functions"""
        console.print("\n[bold cyan]═══ Enumerating Lambda Functions ═══[/bold cyan]")

        try:
            paginator = self.lambda_client.get_paginator("list_functions")

            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    function_name = function.get("FunctionName")
                    console.print(f"\n[bold]Processing:[/bold] {function_name}")

                    # Get detailed configuration
                    func_config = self._get_function_configuration(function_name)

                    if not func_config:
                        continue

                    # Get event source mappings
                    if self.options.get("ENUMERATE_EVENT_SOURCES"):
                        event_sources = self._get_event_source_mappings(function_name)
                        func_config["event_sources"] = event_sources

                        # Add to global event source list
                        for event_source in event_sources:
                            self.data["event_source_mappings"].append(
                                {"function_name": function_name, **event_source}
                            )

                    # Check for security findings
                    findings = self._check_function_security(func_config)
                    func_config["security_findings"] = findings
                    self.data["security_findings"].extend(findings)

                    # Track special configurations
                    runtime = func_config.get("runtime", "")
                    if runtime in self.deprecated_runtimes:
                        self.data["deprecated_runtimes"].append(function_name)

                    if func_config.get("vpc_config", {}).get("VpcId"):
                        self.data["vpc_functions"].append(function_name)

                    if func_config.get("dead_letter_config"):
                        self.data["functions_with_dlq"].append(function_name)

                    self.data["functions"].append(func_config)
                    self.data["total_functions"] += 1

                    # Display function panel
                    self._display_function_panel(func_config)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_functions']} Lambda functions"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating functions: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _display_function_panel(self, func_info: Dict[str, Any]):
        """Display function information in a formatted panel"""
        runtime = func_info.get("runtime", "Unknown")
        runtime_status = (
            "⚠️ Deprecated" if runtime in self.deprecated_runtimes else "✓ Current"
        )

        vpc_status = (
            "🔒 VPC" if func_info.get("vpc_config", {}).get("VpcId") else "🌐 No VPC"
        )
        dlq_status = (
            "✓ Configured" if func_info.get("dead_letter_config") else "✗ Not Set"
        )

        # Security status
        security_status = []
        if runtime not in self.deprecated_runtimes:
            security_status.append("[green]✓ Current Runtime[/green]")
        else:
            security_status.append("[red]⚠ Deprecated Runtime[/red]")

        if func_info.get("vpc_config", {}).get("VpcId"):
            security_status.append("[green]✓ VPC Isolated[/green]")

        if func_info.get("tracing_config", {}).get("Mode") == "Active":
            security_status.append("[green]✓ X-Ray Tracing[/green]")

        panel_content = (
            f"[bold]ARN:[/bold] {func_info.get('arn', 'N/A')}\n"
            f"[bold]Runtime:[/bold] {runtime} ({runtime_status})\n"
            f"[bold]Handler:[/bold] {func_info.get('handler', 'N/A')}\n"
            f"[bold]Package Type:[/bold] {func_info.get('package_type', 'Zip')}\n\n"
            f"[bold cyan]Configuration:[/bold cyan]\n"
            f"  Memory: {func_info.get('memory_size', 0)} MB | "
            f"Timeout: {func_info.get('timeout', 0)}s | "
            f"Code Size: {func_info.get('code_size', 0) / 1024:.2f} KB\n"
            f"  Architecture: {', '.join(func_info.get('architectures', ['x86_64']))}\n"
            f"  State: {func_info.get('state', 'Unknown')}\n\n"
            f"[bold cyan]Security:[/bold cyan]\n"
            f"  VPC: {vpc_status}\n"
            f"  Dead Letter Queue: {dlq_status}\n"
            f"  Status: {' | '.join(security_status)}\n\n"
        )

        if func_info.get("vpc_config", {}).get("VpcId"):
            vpc = func_info.get("vpc_config", {})
            panel_content += (
                f"[bold cyan]VPC Configuration:[/bold cyan]\n"
                f"  VPC ID: {vpc.get('VpcId')}\n"
                f"  Subnets: {len(vpc.get('SubnetIds', []))} | "
                f"Security Groups: {len(vpc.get('SecurityGroupIds', []))}\n\n"
            )

        if func_info.get("layers"):
            panel_content += "[bold cyan]Layers:[/bold cyan]\n"
            for layer in func_info.get("layers", []):
                panel_content += f"  • {layer.get('Arn', 'N/A')}\n"
            panel_content += "\n"

        if func_info.get("event_sources"):
            panel_content += f"[bold cyan]Event Sources:[/bold cyan] {len(func_info.get('event_sources', []))}\n"
            for event_source in func_info.get("event_sources", [])[:3]:
                panel_content += f"  • {event_source.get('EventSourceArn', 'N/A')}\n"
            panel_content += "\n"

        if func_info.get("function_urls"):
            panel_content += "[bold cyan]Function URLs:[/bold cyan]\n"
            for url in func_info.get("function_urls", []):
                panel_content += f"  • {url}\n"
            panel_content += "\n"

        panel_content += (
            f"[bold cyan]Execution:[/bold cyan]\n"
            f"  Role: {func_info.get('role', 'N/A').split('/')[-1]}\n"
            f"  Last Modified: {func_info.get('last_modified', 'N/A')}\n"
        )

        if func_info.get("reserved_concurrent_executions"):
            panel_content += f"  Concurrency Limit: {func_info.get('reserved_concurrent_executions')}\n"

        if func_info.get("tags"):
            panel_content += "\n[bold cyan]Tags:[/bold cyan]\n"
            for tag in func_info.get("tags", [])[:5]:
                panel_content += f"  • {tag.get('Key')}: {tag.get('Value')}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{func_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def _check_function_security(self, func_info: Dict[str, Any]) -> List[str]:
        """Check function for security issues"""
        findings = []
        function_name = func_info.get("name")

        # Check for deprecated runtime
        if func_info.get("runtime") in self.deprecated_runtimes:
            findings.append(
                f"Function '{function_name}' uses deprecated runtime: {func_info.get('runtime')}"
            )

        # Check for missing DLQ
        if not func_info.get("dead_letter_config"):
            findings.append(
                f"Function '{function_name}' has no Dead Letter Queue configured"
            )

        # Check for excessive timeout
        if func_info.get("timeout", 0) > 600:  # 10 minutes
            findings.append(
                f"Function '{function_name}' has excessive timeout: {func_info.get('timeout')}s"
            )

        # Check for X-Ray tracing
        if func_info.get("tracing_config", {}).get("Mode") != "Active":
            findings.append(
                f"Function '{function_name}' does not have X-Ray tracing enabled"
            )

        # Check for environment variables (potential secrets)
        if func_info.get("environment"):
            for key in func_info.get("environment", {}).keys():
                if any(
                    keyword in key.upper()
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN"]
                ):
                    findings.append(
                        f"Function '{function_name}' may have sensitive data in environment variable: {key}"
                    )

        # Check for public function URLs
        if func_info.get("function_urls"):
            findings.append(
                f"Function '{function_name}' has public function URL(s) - verify access controls"
            )

        return findings

    def enumerate_layers(self):
        """Enumerate all Lambda layers"""
        if not self.options.get("ENUMERATE_LAYERS"):
            return

        console.print("\n[bold cyan]═══ Enumerating Lambda Layers ═══[/bold cyan]")

        try:
            paginator = self.lambda_client.get_paginator("list_layers")

            for page in paginator.paginate():
                for layer in page.get("Layers", []):
                    layer_name = layer.get("LayerName")
                    layer_arn = layer.get("LayerArn")
                    latest_version = layer.get("LatestMatchingVersion", {})

                    layer_info = {
                        "name": layer_name,
                        "arn": layer_arn,
                        "version": latest_version.get("Version"),
                        "description": latest_version.get("Description", ""),
                        "created_date": latest_version.get("CreatedDate"),
                        "compatible_runtimes": latest_version.get(
                            "CompatibleRuntimes", []
                        ),
                        "compatible_architectures": latest_version.get(
                            "CompatibleArchitectures", []
                        ),
                    }

                    self.data["layers"].append(layer_info)
                    self.data["total_layers"] += 1

                    console.print(
                        f"  [bold]{layer_name}[/bold] (v{layer_info.get('version')}) - "
                        f"Runtimes: {', '.join(layer_info.get('compatible_runtimes', ['Any']))}"
                    )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_layers']} Lambda layers"
            )

        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error enumerating layers: {str(e)}")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"lambda_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for JSON serialization
            output_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "total_functions": self.data["total_functions"],
                    "total_layers": self.data["total_layers"],
                },
                "summary": {
                    "deprecated_runtimes": len(self.data["deprecated_runtimes"]),
                    "vpc_functions": len(self.data["vpc_functions"]),
                    "functions_with_dlq": len(self.data["functions_with_dlq"]),
                    "total_event_sources": len(self.data["event_source_mappings"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "functions": self.data["functions"],
                "layers": self.data["layers"],
                "event_source_mappings": self.data["event_source_mappings"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute Lambda enumeration"""

        panel = Panel(
            "[bold cyan]AWS Lambda Function Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting functions, layers, event sources, and security configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "error": "Failed to initialize Lambda client",
                "data": self.data,
            }

        # Execute enumeration
        self.enumerate_functions()
        self.enumerate_layers()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]Lambda Functions:[/bold] {self.data['total_functions']} | "
            f"[bold]Layers:[/bold] {self.data['total_layers']}"
        )
        console.print(
            f"  [yellow]⚠[/yellow] Deprecated Runtimes: {len(self.data['deprecated_runtimes'])} | "
            f"[green]✓[/green] VPC Functions: {len(self.data['vpc_functions'])} | "
            f"[green]✓[/green] DLQ Configured: {len(self.data['functions_with_dlq'])}"
        )

        if self.data["security_findings"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Security Findings: {len(self.data['security_findings'])}"
            )
            for finding in self.data["security_findings"][:5]:
                console.print(f"  • {finding}")
            if len(self.data["security_findings"]) > 5:
                console.print(
                    f"  ... and {len(self.data['security_findings']) - 5} more"
                )

        return {
            "success": True,
            "output_file": output_file,
        }
