# Import all the required libraries.
import ssl
import socket
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

# Load domains from txt file. ( Specify the path of the txt file )
with open("domains.txt", "r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

# Function to check SSL expiry of domain
def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                days_left = (expiry_date - datetime.now(timezone.utc)).days
                
                result = f"{domain}: Expires in {days_left} days ({expiry_date.strftime('%Y-%m-%d %H:%M:%S')})"
                if days_left < 15:
                    result += " ⚠️ Expiring soon!"
                print(result) 
                return result
    except ssl.SSLCertVerificationError as e:
        return f"{domain}: ❌ SSL Error - {e}"
    except socket.timeout:
        return f"{domain}: ❌ Connection timed out"
    except socket.gaierror:
        return f"{domain}: ❌ DNS resolution failed"
    except Exception as e:
        return f"{domain}: ❌ Error - {str(e)}"

# Use multithreading to pass domain list to function.
with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(check_ssl_expiry, domains)

# Save results to a file. 
with open("ssl_check_results.txt", "w", encoding="utf-8") as f:
    for res in results:
        f.write(res + "\n")
