import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
import uvicorn
import httpx
import dns.resolver
import dns.rdatatype
import socket
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
import re

# Initialize DNS resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Google and Cloudflare DNS

async def whois_rdap_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup using RDAP (Registration Data Access Protocol)"""
    async with httpx.AsyncClient() as client:
        try:
            # Try to find RDAP server for the TLD
            tld = domain.split('.')[-1]
            rdap_base_urls = {
                'com': 'https://rdap.verisign.com/com/v1',
                'net': 'https://rdap.verisign.com/net/v1',
                'org': 'https://rdap.publicinterestregistry.org/rdap',
                'info': 'https://rdap.afilias.net/rdap',
                'io': 'https://rdap.nic.io',
                'co': 'https://rdap.nic.co',
                'me': 'https://rdap.nic.me',
                'tv': 'https://rdap.nic.tv',
                'app': 'https://rdap.nic.google',
                'dev': 'https://rdap.nic.google',
                'cloud': 'https://rdap.nic.google',
            }
            
            # Use IANA bootstrap if TLD not in our list
            if tld not in rdap_base_urls:
                bootstrap_resp = await client.get(f'https://rdap-bootstrap.arin.net/bootstrap/domain/{domain}')
                if bootstrap_resp.status_code == 200:
                    data = bootstrap_resp.json()
                    if 'services' in data and data['services']:
                        rdap_url = data['services'][0][0][0]
                        resp = await client.get(f'{rdap_url}domain/{domain}')
                        if resp.status_code == 200:
                            return resp.json()
            else:
                base_url = rdap_base_urls[tld]
                resp = await client.get(f'{base_url}/domain/{domain}')
                if resp.status_code == 200:
                    return resp.json()
                    
            # Fallback to basic WHOIS using socket (very limited)
            return {"error": "RDAP lookup failed, limited WHOIS data available"}
            
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

async def dns_lookup(domain: str, record_type: str = 'A') -> List[str]:
    """Perform DNS lookup for a domain"""
    try:
        # Use DNS over HTTPS via Cloudflare
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                'https://cloudflare-dns.com/dns-query',
                params={
                    'name': domain,
                    'type': record_type
                },
                headers={'Accept': 'application/dns-json'}
            )
            if resp.status_code == 200:
                data = resp.json()
                if 'Answer' in data:
                    return [answer['data'] for answer in data['Answer']]
        return []
    except Exception as e:
        return [f"Error: {str(e)}"]

async def check_domain_availability(domain: str) -> bool:
    """Check if a domain is available by attempting DNS resolution"""
    try:
        # First try DNS lookup
        dns_results = await dns_lookup(domain, 'A')
        if dns_results and not any('Error' in str(r) for r in dns_results):
            return False  # Domain has DNS records, likely registered
            
        # Try NS records as backup
        ns_results = await dns_lookup(domain, 'NS')
        if ns_results and not any('Error' in str(r) for r in ns_results):
            return False
            
        # No DNS records found, might be available
        return True
    except:
        return True  # If DNS fails completely, might be available

async def ssl_certificate_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information using crt.sh"""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f'https://crt.sh/?q={domain}&output=json')
            if resp.status_code == 200:
                certs = resp.json()
                if certs:
                    # Get the most recent certificate
                    latest_cert = max(certs, key=lambda x: x.get('id', 0))
                    return {
                        'issuer': latest_cert.get('issuer_name', 'Unknown'),
                        'not_before': latest_cert.get('not_before', 'Unknown'),
                        'not_after': latest_cert.get('not_after', 'Unknown'),
                        'common_name': latest_cert.get('common_name', 'Unknown'),
                        'name_value': latest_cert.get('name_value', 'Unknown'),
                    }
            return {"error": "No SSL certificates found"}
        except Exception as e:
            return {"error": f"SSL lookup failed: {str(e)}"}

async def search_expired_domains(keyword: str = "", tld: str = "") -> List[Dict[str, str]]:
    """Search for expired/expiring domains"""
    async with httpx.AsyncClient() as client:
        try:
            # Using ExpiredDomains.net public data
            url = "https://www.expireddomains.net/deleted-domains/"
            if keyword:
                url = f"https://www.expireddomains.net/domain-name-search/?q={keyword}"
                
            resp = await client.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                domains = []
                
                # Parse the table of domains
                table = soup.find('table', class_='base1')
                if table:
                    rows = table.find_all('tr')[1:11]  # Get first 10 results
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) > 1:
                            domain_cell = cells[0]
                            domain_link = domain_cell.find('a')
                            if domain_link:
                                domain_name = domain_link.text.strip()
                                if not tld or domain_name.endswith(f'.{tld}'):
                                    domains.append({
                                        'domain': domain_name,
                                        'status': 'expired/deleted',
                                        'source': 'expireddomains.net'
                                    })
                return domains
            return []
        except Exception as e:
            return [{"error": f"Search failed: {str(e)}"}]

async def domain_age_check(domain: str) -> Dict[str, Any]:
    """Check domain age and basic info"""
    try:
        # Get WHOIS data
        whois_data = await whois_rdap_lookup(domain)
        
        result = {
            'domain': domain,
            'registered': False,
            'age': 'Unknown',
            'created': 'Unknown',
            'expires': 'Unknown',
            'registrar': 'Unknown'
        }
        
        if 'events' in whois_data:
            for event in whois_data['events']:
                if event.get('eventAction') == 'registration':
                    result['created'] = event.get('eventDate', 'Unknown')
                    result['registered'] = True
                    # Calculate age
                    try:
                        created_date = datetime.fromisoformat(event['eventDate'].replace('Z', '+00:00'))
                        age_days = (datetime.now() - created_date.replace(tzinfo=None)).days
                        result['age'] = f"{age_days} days ({age_days // 365} years)"
                    except:
                        pass
                elif event.get('eventAction') == 'expiration':
                    result['expires'] = event.get('eventDate', 'Unknown')
                    
        if 'entities' in whois_data:
            for entity in whois_data['entities']:
                if 'registrar' in entity.get('roles', []):
                    result['registrar'] = entity.get('vcardArray', [['', [['', '', '', 'Unknown']]]])[1][0][3]
                    
        return result
    except Exception as e:
        return {'domain': domain, 'error': str(e)}

async def bulk_domain_check(domains: List[str]) -> List[Dict[str, Any]]:
    """Check availability of multiple domains"""
    results = []
    for domain in domains[:10]:  # Limit to 10 domains to avoid rate limiting
        available = await check_domain_availability(domain)
        results.append({
            'domain': domain,
            'available': available,
            'status': 'available' if available else 'registered'
        })
    return results

async def get_dns_records(domain: str) -> Dict[str, Any]:
    """Get all DNS records for a domain"""
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    results = {}
    
    for record_type in record_types:
        records = await dns_lookup(domain, record_type)
        if records and not any('Error' in str(r) for r in records):
            results[record_type] = records
            
    return results

@click.command()
@click.option("--port", default=8080, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="sse",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    # Create MCP server
    app = Server("domain-mcp-server")

    # Register tools
    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="whois_lookup",
                description="Get WHOIS information for a domain using RDAP protocol",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to lookup (e.g., example.com)"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="dns_lookup",
                description="Get DNS records for a domain",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to lookup"
                        },
                        "record_type": {
                            "type": "string",
                            "description": "DNS record type (A, AAAA, MX, TXT, NS, CNAME, SOA)",
                            "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"],
                            "default": "A"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="check_domain_availability",
                description="Check if a domain is available for registration",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to check"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="ssl_certificate_info",
                description="Get SSL certificate information for a domain",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to check SSL certificates"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="search_expired_domains",
                description="Search for expired or deleted domains",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "keyword": {
                            "type": "string",
                            "description": "Keyword to search for in domain names",
                            "default": ""
                        },
                        "tld": {
                            "type": "string",
                            "description": "Top-level domain to filter by (e.g., com, net, org)",
                            "default": ""
                        }
                    },
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="domain_age_check",
                description="Check domain age and registration dates",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to check"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="bulk_domain_check",
                description="Check availability of multiple domains at once",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of domain names to check (max 10)"
                        }
                    },
                    "required": ["domains"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_dns_records",
                description="Get all DNS records for a domain",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to get all DNS records"
                        }
                    },
                    "required": ["domain"],
                    "additionalProperties": False
                }
            )
        ]

    @app.call_tool()
    async def handle_tool(name: str, arguments: dict) -> list[types.TextContent]:
        try:
            if name == "whois_lookup":
                result = await whois_rdap_lookup(arguments["domain"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps(result, indent=2)
                )]
            
            elif name == "dns_lookup":
                records = await dns_lookup(
                    arguments["domain"],
                    arguments.get("record_type", "A")
                )
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "domain": arguments["domain"],
                        "record_type": arguments.get("record_type", "A"),
                        "records": records
                    }, indent=2)
                )]
            
            elif name == "check_domain_availability":
                available = await check_domain_availability(arguments["domain"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "domain": arguments["domain"],
                        "available": available,
                        "status": "available" if available else "registered"
                    }, indent=2)
                )]
            
            elif name == "ssl_certificate_info":
                cert_info = await ssl_certificate_info(arguments["domain"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps(cert_info, indent=2)
                )]
            
            elif name == "search_expired_domains":
                domains = await search_expired_domains(
                    arguments.get("keyword", ""),
                    arguments.get("tld", "")
                )
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "search_params": {
                            "keyword": arguments.get("keyword", ""),
                            "tld": arguments.get("tld", "")
                        },
                        "results": domains,
                        "count": len(domains)
                    }, indent=2)
                )]
            
            elif name == "domain_age_check":
                age_info = await domain_age_check(arguments["domain"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps(age_info, indent=2)
                )]
            
            elif name == "bulk_domain_check":
                results = await bulk_domain_check(arguments["domains"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "checked": len(results),
                        "results": results
                    }, indent=2)
                )]
            
            elif name == "get_dns_records":
                records = await get_dns_records(arguments["domain"])
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "domain": arguments["domain"],
                        "records": records
                    }, indent=2)
                )]
            
            else:
                raise ValueError(f"Unknown tool: {name}")
                
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "error": str(e),
                    "tool": name,
                    "arguments": arguments
                }, indent=2)
            )]

    # Handle different transport types
    if transport == "sse":
        # Set up SSE transport
        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await app.run(
                    streams[0], 
                    streams[1], 
                    app.create_initialization_options()
                )

        # Create Starlette app
        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        # Run server
        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    else:
        # Handle stdio transport
        async def arun():
            from mcp.server.stdio import stdio_server
            async with stdio_server() as streams:
                await app.run(
                    streams[0], 
                    streams[1], 
                    app.create_initialization_options()
                )
        anyio.run(arun)

    return 0

if __name__ == "__main__":
    main()