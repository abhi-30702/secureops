import json
import os
import subprocess


def run(domain: str, sources: str, output_file: str) -> list[dict]:
    """
    Execute theHarvester CLI and parse results.

    Args:
        domain: Target domain
        sources: Comma-separated sources (e.g., "crtsh" or "all")
        output_file: Output file path (without .json extension)

    Returns:
        List of dicts: {item_type, value, source}
        Returns [] on any error — never raises.
    """
    try:
        # Build command
        cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", output_file]

        # Run subprocess with 180 second timeout
        result = subprocess.run(
            cmd,
            timeout=180,
            capture_output=True,
            text=True,
        )

        # theHarvester adds .json to the output_file automatically
        json_path = f"{output_file}.json"

        # Read and parse the JSON output
        with open(json_path, "r") as f:
            data = json.load(f)

        # Parse results, deduplicating with a set
        seen = set()
        results = []

        # Parse emails
        for email in data.get("emails", []):
            email = str(email).strip()
            if email and email not in seen:
                seen.add(email)
                results.append({
                    "item_type": "email",
                    "value": email,
                    "source": "theharvester"
                })

        # Parse hosts (subdomains)
        for host in data.get("hosts", []):
            host = str(host).strip()
            if host:
                # If "host:ip" format, take only the part before the colon
                if ":" in host:
                    host = host.split(":", 1)[0]
                if host and host not in seen:
                    seen.add(host)
                    results.append({
                        "item_type": "subdomain",
                        "value": host,
                        "source": "theharvester"
                    })

        # Parse IPs
        for ip in data.get("ips", []):
            ip = str(ip).strip()
            if ip and ip not in seen:
                seen.add(ip)
                results.append({
                    "item_type": "ip",
                    "value": ip,
                    "source": "theharvester"
                })

        # Parse URLs
        for url in data.get("interesting_urls", []):
            url = str(url).strip()
            if url and url not in seen:
                seen.add(url)
                results.append({
                    "item_type": "url",
                    "value": url,
                    "source": "theharvester"
                })

        # Clean up the JSON file
        try:
            os.unlink(json_path)
        except FileNotFoundError:
            pass

        return results

    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    except Exception:
        # Catch any other exception and return empty list
        return []
