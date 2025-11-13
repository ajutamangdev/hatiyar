"""AWS Route53 Enumeration Module"""

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
    """AWS Route53 DNS enumeration including hosted zones, records, health checks, and DNSSEC analysis."""

    NAME = "route53_enumeration"
    DESCRIPTION = "AWS Route53 DNS and domain enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",  # Route53 is global, but client needs a region
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_HOSTED_ZONES": True,  # Enumerate hosted zones
        "ENUMERATE_HEALTH_CHECKS": True,  # Enumerate health checks
        "ENUMERATE_TRAFFIC_POLICIES": True,  # Enumerate traffic policies
        "ENUMERATE_DOMAINS": True,  # Enumerate registered domains
        "DETAILED_RECORDS": True,  # Get detailed record information
        "OUTPUT_FILE": "route53_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.route53_client = None
        self.route53domains_client = None
        self.data = {
            "hosted_zones": [],
            "record_sets": [],
            "health_checks": [],
            "traffic_policies": [],
            "domains": [],
            "query_logging_configs": [],
            "security_findings": [],
            "total_hosted_zones": 0,
            "total_record_sets": 0,
            "total_health_checks": 0,
            "total_domains": 0,
            "public_zones": [],
            "private_zones": [],
            "dnssec_enabled_zones": [],
        }

    def initialize_client(self) -> bool:
        """Initialize AWS Route53 client with multiple credential options"""
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
            self.route53_client = session.client("route53")
            self.route53domains_client = session.client(
                "route53domains", region_name="us-east-1"
            )

            # Test connection
            self.route53_client.list_hosted_zones_by_name(MaxItems="1")
            console.print("[green]✓[/green] Successfully connected to AWS Route53")
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
            console.print(f"[red]✗[/red] Failed to initialize Route53 client: {str(e)}")
            return False

    def enumerate_hosted_zones(self):
        """Enumerate all Route53 hosted zones"""
        if not self.options.get("ENUMERATE_HOSTED_ZONES"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Route53 Hosted Zones ═══[/bold cyan]"
        )

        try:
            paginator = self.route53_client.get_paginator("list_hosted_zones")

            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id = zone.get("Id").split("/")[-1]
                    zone_name = zone.get("Name")
                    console.print(f"\n[bold]Processing:[/bold] {zone_name}")

                    # Get zone details
                    zone_details = self.route53_client.get_hosted_zone(Id=zone_id)
                    hosted_zone = zone_details.get("HostedZone", {})
                    delegation_set = zone_details.get("DelegationSet", {})
                    vpcs = zone_details.get("VPCs", [])

                    # Get DNSSEC status
                    dnssec_status = None
                    try:
                        dnssec_response = self.route53_client.get_dnssec(
                            HostedZoneId=zone_id
                        )
                        dnssec_status = dnssec_response.get("Status", {}).get(
                            "ServeSignature"
                        )
                    except ClientError:
                        pass

                    # Get query logging config
                    query_logging_configs = []
                    try:
                        qlc_response = self.route53_client.list_query_logging_configs(
                            HostedZoneId=zone_id
                        )
                        query_logging_configs = qlc_response.get(
                            "QueryLoggingConfigs", []
                        )
                    except ClientError:
                        pass

                    # Get tags
                    tags = []
                    try:
                        tag_response = self.route53_client.list_tags_for_resource(
                            ResourceType="hostedzone", ResourceId=zone_id
                        )
                        tags = tag_response.get("Tags", [])
                    except ClientError:
                        pass

                    zone_info = {
                        "id": zone_id,
                        "name": zone_name,
                        "caller_reference": hosted_zone.get("CallerReference"),
                        "config": hosted_zone.get("Config", {}),
                        "resource_record_set_count": hosted_zone.get(
                            "ResourceRecordSetCount"
                        ),
                        "is_private": hosted_zone.get("Config", {}).get(
                            "PrivateZone", False
                        ),
                        "comment": hosted_zone.get("Config", {}).get("Comment", ""),
                        "name_servers": delegation_set.get("NameServers", []),
                        "vpcs": vpcs,
                        "dnssec_status": dnssec_status,
                        "query_logging_configs": query_logging_configs,
                        "tags": tags,
                        "record_sets": [],
                    }

                    # Enumerate record sets if detailed records enabled
                    if self.options.get("DETAILED_RECORDS"):
                        zone_info["record_sets"] = self._enumerate_record_sets(
                            zone_id, zone_name
                        )

                    # Check for security findings
                    findings = self._check_zone_security(zone_info)
                    zone_info["security_findings"] = findings
                    self.data["security_findings"].extend(findings)

                    # Track zone types
                    if zone_info.get("is_private"):
                        self.data["private_zones"].append(zone_name)
                    else:
                        self.data["public_zones"].append(zone_name)

                    if dnssec_status == "SIGNING":
                        self.data["dnssec_enabled_zones"].append(zone_name)

                    self.data["hosted_zones"].append(zone_info)
                    self.data["total_hosted_zones"] += 1

                    # Display zone panel
                    self._display_zone_panel(zone_info)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_hosted_zones']} hosted zones"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating hosted zones: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _enumerate_record_sets(
        self, zone_id: str, zone_name: str
    ) -> List[Dict[str, Any]]:
        """Enumerate record sets in a hosted zone"""
        record_sets = []

        try:
            paginator = self.route53_client.get_paginator("list_resource_record_sets")

            for page in paginator.paginate(HostedZoneId=zone_id):
                for record in page.get("ResourceRecordSets", []):
                    record_info = {
                        "name": record.get("Name"),
                        "type": record.get("Type"),
                        "ttl": record.get("TTL"),
                        "routing_policy": self._determine_routing_policy(record),
                        "set_identifier": record.get("SetIdentifier"),
                        "weight": record.get("Weight"),
                        "region": record.get("Region"),
                        "geolocation": record.get("GeoLocation"),
                        "failover": record.get("Failover"),
                        "multi_value_answer": record.get("MultiValueAnswer"),
                        "health_check_id": record.get("HealthCheckId"),
                        "traffic_policy_instance_id": record.get(
                            "TrafficPolicyInstanceId"
                        ),
                        "alias_target": record.get("AliasTarget"),
                        "resource_records": record.get("ResourceRecords", []),
                    }

                    record_sets.append(record_info)
                    self.data["record_sets"].append(
                        {"zone_name": zone_name, **record_info}
                    )
                    self.data["total_record_sets"] += 1

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating record sets for {zone_name}: {str(e)}"
            )

        return record_sets

    def _determine_routing_policy(self, record: Dict[str, Any]) -> str:
        """Determine the routing policy for a record"""
        if record.get("Weight") is not None:
            return "Weighted"
        elif record.get("Region"):
            return "Latency"
        elif record.get("GeoLocation"):
            return "Geolocation"
        elif record.get("Failover"):
            return "Failover"
        elif record.get("MultiValueAnswer"):
            return "Multivalue Answer"
        elif record.get("AliasTarget"):
            return "Alias"
        else:
            return "Simple"

    def _display_zone_panel(self, zone_info: Dict[str, Any]):
        """Display hosted zone information in a formatted panel"""
        zone_type = "🔒 Private" if zone_info.get("is_private") else "🌐 Public"
        dnssec_status = (
            "🔐 DNSSEC Enabled"
            if zone_info.get("dnssec_status") == "SIGNING"
            else "🔓 DNSSEC Disabled"
        )

        # Security status
        security_status = []
        if zone_info.get("dnssec_status") == "SIGNING":
            security_status.append("[green]✓ DNSSEC[/green]")
        else:
            security_status.append("[yellow]⚠ No DNSSEC[/yellow]")

        if zone_info.get("query_logging_configs"):
            security_status.append("[green]✓ Query Logging[/green]")

        panel_content = (
            f"[bold]Zone ID:[/bold] {zone_info.get('id')}\n"
            f"[bold]Type:[/bold] {zone_type}\n"
            f"[bold]Record Count:[/bold] {zone_info.get('resource_record_set_count', 0)}\n\n"
            f"[bold cyan]Security:[/bold cyan]\n"
            f"  {dnssec_status}\n"
            f"  Status: {' | '.join(security_status)}\n\n"
        )

        if zone_info.get("comment"):
            panel_content += f"[bold]Comment:[/bold] {zone_info.get('comment')}\n\n"

        if zone_info.get("name_servers"):
            panel_content += f"[bold cyan]Name Servers:[/bold cyan] {len(zone_info.get('name_servers', []))}\n"
            for ns in zone_info.get("name_servers", [])[:4]:
                panel_content += f"  • {ns}\n"
            panel_content += "\n"

        if zone_info.get("is_private") and zone_info.get("vpcs"):
            panel_content += f"[bold cyan]Associated VPCs:[/bold cyan] {len(zone_info.get('vpcs', []))}\n"
            for vpc in zone_info.get("vpcs", []):
                panel_content += f"  • {vpc.get('VPCId')} ({vpc.get('VPCRegion')})\n"
            panel_content += "\n"

        if zone_info.get("query_logging_configs"):
            panel_content += (
                f"[bold cyan]Query Logging:[/bold cyan] ✓ Enabled\n"
                f"  CloudWatch Log Group: {zone_info.get('query_logging_configs', [{}])[0].get('CloudWatchLogsLogGroupArn', 'N/A').split(':')[-1]}\n\n"
            )

        if zone_info.get("record_sets"):
            # Count by type
            record_types: Dict[str, int] = {}
            for record in zone_info.get("record_sets", []):
                rtype = record.get("type")
                record_types[rtype] = record_types.get(rtype, 0) + 1

            panel_content += "[bold cyan]Record Types:[/bold cyan]\n"
            for rtype, count in sorted(record_types.items()):
                panel_content += f"  • {rtype}: {count}\n"
            panel_content += "\n"

            # Show some interesting records
            alias_records = [
                r for r in zone_info.get("record_sets", []) if r.get("alias_target")
            ]
            if alias_records:
                panel_content += (
                    f"[bold cyan]Alias Records:[/bold cyan] {len(alias_records)}\n"
                )
                for alias in alias_records[:3]:
                    target = alias.get("alias_target", {}).get("DNSName", "N/A")
                    panel_content += f"  • {alias.get('name')} → {target}\n"
                if len(alias_records) > 3:
                    panel_content += f"  ... and {len(alias_records) - 3} more\n"
                panel_content += "\n"

        if zone_info.get("tags"):
            panel_content += "[bold cyan]Tags:[/bold cyan]\n"
            for tag in zone_info.get("tags", [])[:5]:
                panel_content += f"  • {tag.get('Key')}: {tag.get('Value')}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{zone_info.get('name')}[/bold]",
                expand=False,
            )
        )

    def _check_zone_security(self, zone_info: Dict[str, Any]) -> List[str]:
        """Check hosted zone for security issues"""
        findings = []
        zone_name = zone_info.get("name")

        # Check for DNSSEC
        if (
            not zone_info.get("is_private")
            and zone_info.get("dnssec_status") != "SIGNING"
        ):
            findings.append(
                f"Public hosted zone '{zone_name}' does not have DNSSEC enabled"
            )

        # Check for query logging
        if not zone_info.get("query_logging_configs"):
            findings.append(
                f"Hosted zone '{zone_name}' does not have query logging enabled"
            )

        # Check for wildcard records (potential security risk)
        for record in zone_info.get("record_sets", []):
            if record.get("name", "").startswith("*"):
                findings.append(
                    f"Hosted zone '{zone_name}' contains wildcard record: {record.get('name')}"
                )

        return findings

    def enumerate_health_checks(self):
        """Enumerate all Route53 health checks"""
        if not self.options.get("ENUMERATE_HEALTH_CHECKS"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Route53 Health Checks ═══[/bold cyan]"
        )

        try:
            paginator = self.route53_client.get_paginator("list_health_checks")

            for page in paginator.paginate():
                for health_check in page.get("HealthChecks", []):
                    hc_id = health_check.get("Id")
                    config = health_check.get("HealthCheckConfig", {})

                    # Get tags
                    tags = []
                    try:
                        tag_response = self.route53_client.list_tags_for_resource(
                            ResourceType="healthcheck", ResourceId=hc_id
                        )
                        tags = tag_response.get("Tags", [])
                    except ClientError:
                        pass

                    hc_info = {
                        "id": hc_id,
                        "version": health_check.get("HealthCheckVersion"),
                        "caller_reference": health_check.get("CallerReference"),
                        "type": config.get("Type"),
                        "resource_path": config.get("ResourcePath"),
                        "fully_qualified_domain_name": config.get(
                            "FullyQualifiedDomainName"
                        ),
                        "ip_address": config.get("IPAddress"),
                        "port": config.get("Port"),
                        "protocol": config.get("Type"),
                        "request_interval": config.get("RequestInterval"),
                        "failure_threshold": config.get("FailureThreshold"),
                        "measure_latency": config.get("MeasureLatency"),
                        "inverted": config.get("Inverted"),
                        "disabled": config.get("Disabled"),
                        "health_threshold": config.get("HealthThreshold"),
                        "child_health_checks": config.get("ChildHealthChecks", []),
                        "enable_sni": config.get("EnableSNI"),
                        "regions": config.get("Regions", []),
                        "alarm_identifier": config.get("AlarmIdentifier"),
                        "insufficient_data_health_status": config.get(
                            "InsufficientDataHealthStatus"
                        ),
                        "tags": tags,
                    }

                    self.data["health_checks"].append(hc_info)
                    self.data["total_health_checks"] += 1

                    status = "🔴 Disabled" if hc_info.get("disabled") else "🟢 Enabled"
                    target = (
                        hc_info.get("fully_qualified_domain_name")
                        or hc_info.get("ip_address")
                        or "Calculated"
                    )

                    console.print(
                        f"  [bold]{hc_id}[/bold] - {hc_info.get('type')} → {target} - {status}"
                    )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_health_checks']} health checks"
            )

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating health checks: {str(e)}"
            )

    def enumerate_traffic_policies(self):
        """Enumerate all Route53 traffic policies"""
        if not self.options.get("ENUMERATE_TRAFFIC_POLICIES"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Route53 Traffic Policies ═══[/bold cyan]"
        )

        try:
            response = self.route53_client.list_traffic_policies()
            policies = response.get("TrafficPolicySummaries", [])

            for policy in policies:
                policy_info = {
                    "id": policy.get("Id"),
                    "name": policy.get("Name"),
                    "type": policy.get("Type"),
                    "latest_version": policy.get("LatestVersion"),
                    "traffic_policy_count": policy.get("TrafficPolicyCount"),
                }

                self.data["traffic_policies"].append(policy_info)

                console.print(
                    f"  [bold]{policy_info.get('name')}[/bold] (v{policy_info.get('latest_version')}) - "
                    f"{policy_info.get('type')}"
                )

            console.print(
                f"\n[green]✓[/green] Found {len(self.data['traffic_policies'])} traffic policies"
            )

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating traffic policies: {str(e)}"
            )

    def enumerate_domains(self):
        """Enumerate registered domains"""
        if not self.options.get("ENUMERATE_DOMAINS"):
            return

        console.print("\n[bold cyan]═══ Enumerating Registered Domains ═══[/bold cyan]")

        try:
            paginator = self.route53domains_client.get_paginator("list_domains")

            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_name = domain.get("DomainName")

                    # Get domain details
                    try:
                        domain_details = self.route53domains_client.get_domain_detail(
                            DomainName=domain_name
                        )

                        domain_info = {
                            "name": domain_name,
                            "auto_renew": domain.get("AutoRenew"),
                            "transfer_lock": domain.get("TransferLock"),
                            "expiry": domain.get("Expiry"),
                            "registrar_name": domain_details.get("RegistrarName"),
                            "registrar_url": domain_details.get("RegistrarUrl"),
                            "abuse_contact_email": domain_details.get(
                                "AbuseContactEmail"
                            ),
                            "abuse_contact_phone": domain_details.get(
                                "AbuseContactPhone"
                            ),
                            "registry_domain_id": domain_details.get(
                                "RegistryDomainId"
                            ),
                            "creation_date": domain_details.get("CreationDate"),
                            "updated_date": domain_details.get("UpdatedDate"),
                            "expiration_date": domain_details.get("ExpirationDate"),
                            "status_list": domain_details.get("StatusList", []),
                            "dnssec": domain_details.get("Dnssec"),
                            "name_servers": domain_details.get("Nameservers", []),
                        }

                        self.data["domains"].append(domain_info)
                        self.data["total_domains"] += 1

                        auto_renew = (
                            "✓ Enabled"
                            if domain_info.get("auto_renew")
                            else "✗ Disabled"
                        )
                        transfer_lock = (
                            "🔒 Locked"
                            if domain_info.get("transfer_lock")
                            else "🔓 Unlocked"
                        )

                        console.print(
                            f"  [bold]{domain_name}[/bold] - "
                            f"Auto-Renew: {auto_renew} | Transfer Lock: {transfer_lock}"
                        )

                    except Exception as e:
                        console.print(
                            f"[yellow]⚠[/yellow] Error getting details for {domain_name}: {str(e)}"
                        )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_domains']} registered domains"
            )

        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
                console.print(
                    "[yellow]⚠[/yellow] No permission to list domains (requires route53domains:ListDomains)"
                )
            else:
                console.print(f"[yellow]⚠[/yellow] Error enumerating domains: {str(e)}")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error enumerating domains: {str(e)}")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"route53_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for JSON serialization
            output_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "total_hosted_zones": self.data["total_hosted_zones"],
                    "total_record_sets": self.data["total_record_sets"],
                    "total_health_checks": self.data["total_health_checks"],
                    "total_domains": self.data["total_domains"],
                },
                "summary": {
                    "public_zones": len(self.data["public_zones"]),
                    "private_zones": len(self.data["private_zones"]),
                    "dnssec_enabled_zones": len(self.data["dnssec_enabled_zones"]),
                    "traffic_policies": len(self.data["traffic_policies"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "hosted_zones": self.data["hosted_zones"],
                "record_sets": self.data["record_sets"],
                "health_checks": self.data["health_checks"],
                "traffic_policies": self.data["traffic_policies"],
                "domains": self.data["domains"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute Route53 enumeration"""

        panel = Panel(
            "[bold cyan]AWS Route53 DNS Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')} (Route53 is global)\n"
            "[dim]Collecting hosted zones, records, health checks, traffic policies, and domains[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "error": "Failed to initialize Route53 client",
                "data": self.data,
            }

        # Execute enumeration
        self.enumerate_hosted_zones()
        self.enumerate_health_checks()
        self.enumerate_traffic_policies()
        self.enumerate_domains()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]Hosted Zones:[/bold] {self.data['total_hosted_zones']} "
            f"(Public: {len(self.data['public_zones'])} | Private: {len(self.data['private_zones'])})"
        )
        console.print(
            f"[bold]Record Sets:[/bold] {self.data['total_record_sets']} | "
            f"[bold]Health Checks:[/bold] {self.data['total_health_checks']} | "
            f"[bold]Domains:[/bold] {self.data['total_domains']}"
        )
        console.print(
            f"  [green]✓[/green] DNSSEC Enabled: {len(self.data['dnssec_enabled_zones'])} zones | "
            f"[bold]Traffic Policies:[/bold] {len(self.data['traffic_policies'])}"
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

        return {"success": True, "output_file": output_file}
