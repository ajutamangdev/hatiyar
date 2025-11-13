"""AWS Container Services Enumeration Module"""

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
    """AWS container services enumeration including ECS, EKS, and ECR with security analysis."""

    NAME = "container_enumeration"
    DESCRIPTION = "AWS ECS, EKS, and ECR enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_ECS": True,  # Enumerate ECS clusters and services
        "ENUMERATE_EKS": True,  # Enumerate EKS clusters
        "ENUMERATE_ECR": True,  # Enumerate ECR repositories
        "SCAN_IMAGES": True,  # Get image scan results
        "OUTPUT_FILE": "container_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.ecs_client = None
        self.eks_client = None
        self.ecr_client = None
        self.data = {
            "ecs_clusters": [],
            "ecs_services": [],
            "ecs_tasks": [],
            "ecs_task_definitions": [],
            "eks_clusters": [],
            "eks_node_groups": [],
            "ecr_repositories": [],
            "ecr_images": [],
            "security_findings": [],
            "total_ecs_clusters": 0,
            "total_ecs_services": 0,
            "total_eks_clusters": 0,
            "total_ecr_repositories": 0,
            "vulnerable_images": [],
            "public_repositories": [],
        }

    def initialize_client(self) -> bool:
        """Initialize AWS container service clients with multiple credential options"""
        try:
            session_kwargs = {"region_name": self.options.get("AWS_REGION")}

            # Check for AWS profile first
            if self.options.get("AWS_PROFILE"):
                session_kwargs["profile_name"] = self.options.get("AWS_PROFILE")
                console.print(
                    f"[dim]Using AWS Profile: {self.options.get('AWS_PROFILE')}[/dim]"
                )
            # Check for explicit credentials
            elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
                session_kwargs["aws_access_key_id"] = self.options.get("ACCESS_KEY")
                session_kwargs["aws_secret_access_key"] = self.options.get("SECRET_KEY")
                if self.options.get("SESSION_TOKEN"):
                    session_kwargs["aws_session_token"] = self.options.get(
                        "SESSION_TOKEN"
                    )
                console.print("[dim]Using provided AWS credentials[/dim]")
            else:
                console.print("[dim]Using default AWS credentials[/dim]")

            session = boto3.Session(**session_kwargs)
            self.ecs_client = session.client("ecs")
            self.eks_client = session.client("eks")
            self.ecr_client = session.client("ecr")

            # Test connection
            self.ecs_client.list_clusters(maxResults=1)
            console.print(
                "[green]✓[/green] Successfully connected to AWS Container Services"
            )
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
            console.print(
                f"[red]✗[/red] Failed to initialize container clients: {str(e)}"
            )
            return False

    def enumerate_ecs_clusters(self):
        """Enumerate all ECS clusters"""
        if not self.options.get("ENUMERATE_ECS"):
            return

        console.print("\n[bold cyan]═══ Enumerating ECS Clusters ═══[/bold cyan]")

        try:
            # List all cluster ARNs
            cluster_arns = []
            paginator = self.ecs_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            if not cluster_arns:
                console.print("[dim]No ECS clusters found[/dim]")
                return

            # Describe clusters in batches of 100
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i : i + 100]
                response = self.ecs_client.describe_clusters(
                    clusters=batch, include=["TAGS", "SETTINGS", "STATISTICS"]
                )

                for cluster in response.get("clusters", []):
                    cluster_name = cluster.get("clusterName")
                    console.print(f"\n[bold]Processing:[/bold] {cluster_name}")

                    cluster_info = {
                        "name": cluster_name,
                        "arn": cluster.get("clusterArn"),
                        "status": cluster.get("status"),
                        "registered_container_instances": cluster.get(
                            "registeredContainerInstancesCount"
                        ),
                        "running_tasks": cluster.get("runningTasksCount"),
                        "pending_tasks": cluster.get("pendingTasksCount"),
                        "active_services": cluster.get("activeServicesCount"),
                        "statistics": cluster.get("statistics", []),
                        "settings": cluster.get("settings", []),
                        "tags": cluster.get("tags", []),
                        "services": [],
                    }

                    # Enumerate services for this cluster
                    cluster_info["services"] = self._enumerate_cluster_services(
                        cluster.get("clusterArn")
                    )

                    # Check for security findings
                    findings = self._check_ecs_cluster_security(cluster_info)
                    cluster_info["security_findings"] = findings
                    self.data["security_findings"].extend(findings)

                    self.data["ecs_clusters"].append(cluster_info)
                    self.data["total_ecs_clusters"] += 1

                    # Display cluster panel
                    self._display_ecs_cluster_panel(cluster_info)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_ecs_clusters']} ECS clusters"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating ECS clusters: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _enumerate_cluster_services(self, cluster_arn: str) -> List[Dict[str, Any]]:
        """Enumerate services in an ECS cluster"""
        services: List[Dict[str, Any]] = []

        try:
            # List service ARNs
            service_arns = []
            paginator = self.ecs_client.get_paginator("list_services")
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))

            if not service_arns:
                return services

            # Describe services in batches of 10
            for i in range(0, len(service_arns), 10):
                batch = service_arns[i : i + 10]
                response = self.ecs_client.describe_services(
                    cluster=cluster_arn, services=batch, include=["TAGS"]
                )

                for service in response.get("services", []):
                    service_info = {
                        "name": service.get("serviceName"),
                        "arn": service.get("serviceArn"),
                        "status": service.get("status"),
                        "desired_count": service.get("desiredCount"),
                        "running_count": service.get("runningCount"),
                        "pending_count": service.get("pendingCount"),
                        "launch_type": service.get("launchType"),
                        "platform_version": service.get("platformVersion"),
                        "task_definition": service.get("taskDefinition"),
                        "load_balancers": service.get("loadBalancers", []),
                        "network_configuration": service.get("networkConfiguration"),
                        "health_check_grace_period": service.get(
                            "healthCheckGracePeriodSeconds"
                        ),
                        "scheduling_strategy": service.get("schedulingStrategy"),
                        "deployment_configuration": service.get(
                            "deploymentConfiguration"
                        ),
                        "tags": service.get("tags", []),
                    }

                    services.append(service_info)
                    self.data["ecs_services"].append(service_info)
                    self.data["total_ecs_services"] += 1

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating services for cluster: {str(e)}"
            )

        return services

    def _display_ecs_cluster_panel(self, cluster_info: Dict[str, Any]):
        """Display ECS cluster information in a formatted panel"""

        panel_content = (
            f"[bold]ARN:[/bold] {cluster_info.get('arn', 'N/A')}\n"
            f"[bold]Status:[/bold] {cluster_info.get('status')}\n\n"
            f"[bold cyan]Resources:[/bold cyan]\n"
            f"  Container Instances: {cluster_info.get('registered_container_instances', 0)}\n"
            f"  Active Services: {cluster_info.get('active_services', 0)}\n"
            f"  Running Tasks: {cluster_info.get('running_tasks', 0)}\n"
            f"  Pending Tasks: {cluster_info.get('pending_tasks', 0)}\n\n"
        )

        if cluster_info.get("services"):
            panel_content += f"[bold cyan]Services:[/bold cyan] {len(cluster_info.get('services', []))}\n"
            for service in cluster_info.get("services", [])[:5]:
                launch_type = service.get("launch_type", "EC2")
                panel_content += (
                    f"  • {service.get('name')} ({launch_type}) - "
                    f"Running: {service.get('running_count')}/{service.get('desired_count')}\n"
                )
            if len(cluster_info.get("services", [])) > 5:
                panel_content += (
                    f"  ... and {len(cluster_info.get('services', [])) - 5} more\n"
                )
            panel_content += "\n"

        if cluster_info.get("settings"):
            panel_content += "[bold cyan]Settings:[/bold cyan]\n"
            for setting in cluster_info.get("settings", []):
                panel_content += f"  • {setting.get('name')}: {setting.get('value')}\n"
            panel_content += "\n"

        if cluster_info.get("tags"):
            panel_content += "[bold cyan]Tags:[/bold cyan]\n"
            for tag in cluster_info.get("tags", [])[:5]:
                panel_content += f"  • {tag.get('key')}: {tag.get('value')}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{cluster_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def _check_ecs_cluster_security(self, cluster_info: Dict[str, Any]) -> List[str]:
        """Check ECS cluster for security issues"""
        findings = []
        cluster_name = cluster_info.get("name")

        # Check for container insights
        settings = cluster_info.get("settings", [])
        container_insights = any(
            s.get("name") == "containerInsights" and s.get("value") == "enabled"
            for s in settings
        )

        if not container_insights:
            findings.append(
                f"ECS cluster '{cluster_name}' does not have Container Insights enabled"
            )

        # Check for services without load balancers
        for service in cluster_info.get("services", []):
            if not service.get("load_balancers"):
                findings.append(
                    f"ECS service '{service.get('name')}' in cluster '{cluster_name}' has no load balancer configured"
                )

        return findings

    def enumerate_eks_clusters(self):
        """Enumerate all EKS clusters"""
        if not self.options.get("ENUMERATE_EKS"):
            return

        console.print("\n[bold cyan]═══ Enumerating EKS Clusters ═══[/bold cyan]")

        try:
            # List all cluster names
            cluster_names = self.eks_client.list_clusters().get("clusters", [])

            if not cluster_names:
                console.print("[dim]No EKS clusters found[/dim]")
                return

            for cluster_name in cluster_names:
                console.print(f"\n[bold]Processing:[/bold] {cluster_name}")

                # Describe cluster
                cluster_desc = self.eks_client.describe_cluster(name=cluster_name)
                cluster = cluster_desc.get("cluster", {})

                # Get node groups
                node_groups = []
                try:
                    ng_response = self.eks_client.list_nodegroups(
                        clusterName=cluster_name
                    )
                    ng_names = ng_response.get("nodegroups", [])

                    for ng_name in ng_names:
                        ng_desc = self.eks_client.describe_nodegroup(
                            clusterName=cluster_name, nodegroupName=ng_name
                        )
                        node_group = ng_desc.get("nodegroup", {})

                        ng_info = {
                            "name": ng_name,
                            "arn": node_group.get("nodegroupArn"),
                            "status": node_group.get("status"),
                            "instance_types": node_group.get("instanceTypes", []),
                            "desired_size": node_group.get("scalingConfig", {}).get(
                                "desiredSize"
                            ),
                            "min_size": node_group.get("scalingConfig", {}).get(
                                "minSize"
                            ),
                            "max_size": node_group.get("scalingConfig", {}).get(
                                "maxSize"
                            ),
                            "ami_type": node_group.get("amiType"),
                            "capacity_type": node_group.get("capacityType"),
                            "disk_size": node_group.get("diskSize"),
                        }
                        node_groups.append(ng_info)
                        self.data["eks_node_groups"].append(ng_info)

                except Exception as e:
                    console.print(
                        f"[yellow]⚠[/yellow] Error getting node groups: {str(e)}"
                    )

                cluster_info = {
                    "name": cluster_name,
                    "arn": cluster.get("arn"),
                    "version": cluster.get("version"),
                    "endpoint": cluster.get("endpoint"),
                    "role_arn": cluster.get("roleArn"),
                    "status": cluster.get("status"),
                    "created_at": cluster.get("createdAt"),
                    "platform_version": cluster.get("platformVersion"),
                    "vpc_config": cluster.get("resourcesVpcConfig"),
                    "logging": cluster.get("logging"),
                    "encryption_config": cluster.get("encryptionConfig", []),
                    "tags": cluster.get("tags", {}),
                    "node_groups": node_groups,
                }

                self.data["eks_clusters"].append(cluster_info)
                self.data["total_eks_clusters"] += 1

                # Display cluster panel
                self._display_eks_cluster_panel(cluster_info)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_eks_clusters']} EKS clusters"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating EKS clusters: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _display_eks_cluster_panel(self, cluster_info: Dict[str, Any]):
        """Display EKS cluster information in a formatted panel"""

        vpc_config = cluster_info.get("vpc_config", {})
        public_access = (
            "🌐 Public" if vpc_config.get("endpointPublicAccess") else "🔒 Private"
        )
        encryption = (
            "🔐 Encrypted"
            if cluster_info.get("encryption_config")
            else "🔓 Not Encrypted"
        )

        panel_content = (
            f"[bold]ARN:[/bold] {cluster_info.get('arn', 'N/A')}\n"
            f"[bold]Version:[/bold] {cluster_info.get('version')}\n"
            f"[bold]Status:[/bold] {cluster_info.get('status')}\n"
            f"[bold]Platform Version:[/bold] {cluster_info.get('platform_version')}\n\n"
            f"[bold cyan]Endpoint:[/bold cyan]\n"
            f"  URL: {cluster_info.get('endpoint', 'N/A')}\n"
            f"  Access: {public_access}\n"
            f"  Encryption: {encryption}\n\n"
            f"[bold cyan]VPC Configuration:[/bold cyan]\n"
            f"  VPC: {vpc_config.get('vpcId', 'N/A')}\n"
            f"  Subnets: {len(vpc_config.get('subnetIds', []))}\n"
            f"  Security Groups: {len(vpc_config.get('securityGroupIds', []))}\n"
            f"  Public Access: {vpc_config.get('endpointPublicAccess', False)}\n"
            f"  Private Access: {vpc_config.get('endpointPrivateAccess', False)}\n\n"
        )

        if cluster_info.get("node_groups"):
            panel_content += f"[bold cyan]Node Groups:[/bold cyan] {len(cluster_info.get('node_groups', []))}\n"
            for ng in cluster_info.get("node_groups", []):
                panel_content += (
                    f"  • {ng.get('name')} ({ng.get('capacity_type', 'ON_DEMAND')}) - "
                    f"Nodes: {ng.get('desired_size')}/{ng.get('max_size')} | "
                    f"Type: {', '.join(ng.get('instance_types', ['unknown']))}\n"
                )
            panel_content += "\n"

        logging = cluster_info.get("logging", {}).get("clusterLogging", [])
        if logging:
            enabled_logs = [
                log_type
                for log_setup in logging
                if log_setup.get("enabled")
                for log_type in log_setup.get("types", [])
            ]
            if enabled_logs:
                panel_content += (
                    f"[bold cyan]Logging:[/bold cyan] {', '.join(enabled_logs)}\n\n"
                )

        if cluster_info.get("tags"):
            panel_content += "[bold cyan]Tags:[/bold cyan]\n"
            for key, value in list(cluster_info.get("tags", {}).items())[:5]:
                panel_content += f"  • {key}: {value}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{cluster_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def enumerate_ecr_repositories(self):
        """Enumerate all ECR repositories"""
        if not self.options.get("ENUMERATE_ECR"):
            return

        console.print("\n[bold cyan]═══ Enumerating ECR Repositories ═══[/bold cyan]")

        try:
            paginator = self.ecr_client.get_paginator("describe_repositories")

            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    repo_name = repo.get("repositoryName")
                    console.print(f"\n[bold]Processing:[/bold] {repo_name}")

                    # Get repository policy
                    repo_policy = None
                    try:
                        policy_response = self.ecr_client.get_repository_policy(
                            repositoryName=repo_name
                        )
                        repo_policy = policy_response.get("policyText")
                    except ClientError:
                        pass

                    # Get lifecycle policy
                    lifecycle_policy = None
                    try:
                        lifecycle_response = self.ecr_client.get_lifecycle_policy(
                            repositoryName=repo_name
                        )
                        lifecycle_policy = lifecycle_response.get("lifecyclePolicyText")
                    except ClientError:
                        pass

                    # Get images
                    images = []
                    try:
                        image_paginator = self.ecr_client.get_paginator("list_images")
                        for image_page in image_paginator.paginate(
                            repositoryName=repo_name
                        ):
                            for image in image_page.get("imageIds", []):
                                image_tag = image.get("imageTag", "untagged")
                                image_digest = image.get("imageDigest")

                                # Get image scan findings if enabled
                                scan_findings = None
                                if self.options.get("SCAN_IMAGES"):
                                    try:
                                        scan_response = self.ecr_client.describe_image_scan_findings(
                                            repositoryName=repo_name, imageId=image
                                        )
                                        scan_status = scan_response.get(
                                            "imageScanStatus", {}
                                        )
                                        findings_summary = scan_response.get(
                                            "imageScanFindings", {}
                                        ).get("findingSeverityCounts", {})

                                        scan_findings = {
                                            "status": scan_status.get("status"),
                                            "description": scan_status.get(
                                                "description"
                                            ),
                                            "findings": findings_summary,
                                        }

                                        # Track vulnerable images
                                        if findings_summary:
                                            self.data["vulnerable_images"].append(
                                                {
                                                    "repository": repo_name,
                                                    "tag": image_tag,
                                                    "findings": findings_summary,
                                                }
                                            )

                                    except ClientError:
                                        pass

                                images.append(
                                    {
                                        "tag": image_tag,
                                        "digest": image_digest,
                                        "scan_findings": scan_findings,
                                    }
                                )

                    except Exception as e:
                        console.print(
                            f"[yellow]⚠[/yellow] Error getting images: {str(e)}"
                        )

                    repo_info = {
                        "name": repo_name,
                        "arn": repo.get("repositoryArn"),
                        "uri": repo.get("repositoryUri"),
                        "created_at": repo.get("createdAt"),
                        "image_tag_mutability": repo.get("imageTagMutability"),
                        "image_scanning_enabled": repo.get(
                            "imageScanningConfiguration", {}
                        ).get("scanOnPush", False),
                        "encryption_type": repo.get("encryptionConfiguration", {}).get(
                            "encryptionType", "AES256"
                        ),
                        "kms_key": repo.get("encryptionConfiguration", {}).get(
                            "kmsKey"
                        ),
                        "policy": repo_policy,
                        "lifecycle_policy": lifecycle_policy,
                        "images": images,
                        "image_count": len(images),
                    }

                    self.data["ecr_repositories"].append(repo_info)
                    self.data["total_ecr_repositories"] += 1

                    # Display repository info
                    scan_status = (
                        "✓ Enabled"
                        if repo_info.get("image_scanning_enabled")
                        else "✗ Disabled"
                    )
                    encryption = repo_info.get("encryption_type", "AES256")

                    console.print(
                        f"  [bold]{repo_name}[/bold] - Images: {repo_info.get('image_count')} | "
                        f"Scan: {scan_status} | Encryption: {encryption}"
                    )

                    # Show vulnerable images
                    vulnerable_count = sum(
                        1
                        for img in images
                        if img.get("scan_findings", {}).get("findings")
                    )
                    if vulnerable_count > 0:
                        console.print(
                            f"  [red]⚠[/red] {vulnerable_count} images with vulnerabilities found"
                        )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_ecr_repositories']} ECR repositories"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating ECR repositories: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"container_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for JSON serialization
            output_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "total_ecs_clusters": self.data["total_ecs_clusters"],
                    "total_ecs_services": self.data["total_ecs_services"],
                    "total_eks_clusters": self.data["total_eks_clusters"],
                    "total_ecr_repositories": self.data["total_ecr_repositories"],
                },
                "summary": {
                    "vulnerable_images": len(self.data["vulnerable_images"]),
                    "public_repositories": len(self.data["public_repositories"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "ecs_clusters": self.data["ecs_clusters"],
                "ecs_services": self.data["ecs_services"],
                "eks_clusters": self.data["eks_clusters"],
                "eks_node_groups": self.data["eks_node_groups"],
                "ecr_repositories": self.data["ecr_repositories"],
                "vulnerable_images": self.data["vulnerable_images"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute container services enumeration"""

        panel = Panel(
            "[bold cyan]AWS Container Services Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting ECS, EKS, ECR, and container security configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "error": "Failed to initialize container clients",
            }

        # Execute enumeration
        self.enumerate_ecs_clusters()
        self.enumerate_eks_clusters()
        self.enumerate_ecr_repositories()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]ECS Clusters:[/bold] {self.data['total_ecs_clusters']} | "
            f"[bold]ECS Services:[/bold] {self.data['total_ecs_services']}"
        )
        console.print(
            f"[bold]EKS Clusters:[/bold] {self.data['total_eks_clusters']} | "
            f"[bold]Node Groups:[/bold] {len(self.data['eks_node_groups'])}"
        )
        console.print(
            f"[bold]ECR Repositories:[/bold] {self.data['total_ecr_repositories']} | "
            f"[bold]Total Images:[/bold] {sum(repo.get('image_count', 0) for repo in self.data['ecr_repositories'])}"
        )

        if self.data["vulnerable_images"]:
            console.print(
                f"\n[red]⚠[/red] Vulnerable Images: {len(self.data['vulnerable_images'])}"
            )
            for vuln_image in self.data["vulnerable_images"][:5]:
                findings = vuln_image.get("findings", {})
                console.print(
                    f"  • {vuln_image.get('repository')}:{vuln_image.get('tag')} - "
                    f"Critical: {findings.get('CRITICAL', 0)}, "
                    f"High: {findings.get('HIGH', 0)}, "
                    f"Medium: {findings.get('MEDIUM', 0)}"
                )
            if len(self.data["vulnerable_images"]) > 5:
                console.print(
                    f"  ... and {len(self.data['vulnerable_images']) - 5} more"
                )

        if self.data["security_findings"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Security Findings: {len(self.data['security_findings'])}"
            )
            for finding in self.data["security_findings"][:3]:
                console.print(f"  • {finding}")
            if len(self.data["security_findings"]) > 3:
                console.print(
                    f"  ... and {len(self.data['security_findings']) - 3} more"
                )

        return {"success": True, "output_file": output_file}
