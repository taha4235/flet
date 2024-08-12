import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor
from flet import *
import scapy.all as scapy
import requests as req
from bs4 import BeautifulSoup as bc
import ssl
import os
from urllib.parse import urlparse

def send_ping(ip, packet_count, textarea):
    for i in range(1, packet_count + 1):
        response = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True)
        if "Reply from" in response.stdout:
            textarea.value += f"Packet {i} sent to {ip} - Success\n"
        else:
            textarea.value += f"Packet {i} sent to {ip} - Failed\n"
        textarea.update()

def scan_port(ip, port, textarea):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            textarea.value += f"Port {port}: OPEN\n"
        else:
            textarea.value += f"Port {port}: CLOSED\n"
        textarea.update()
        sock.close()
    except socket.error:
        textarea.value += f"Could not connect to {ip}\n"
        textarea.update()

def scan_ports(ip, start_port, end_port, textarea):
    textarea.value += f"Scanning {ip} from port {start_port} to {end_port}...\n"
    textarea.update()
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port, textarea)

def check_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return f"{hostname} has a valid SSL/TLS certificate\n"
    except ssl.SSLError as e:
        return f"{hostname} has an invalid SSL/TLS certificate: {str(e)}\n"
    except Exception as e:
        return f"Could not connect to {hostname} to check SSL/TLS: {str(e)}\n"
    return ""

def download_robots_txt(website, content):
    parsed_url = urlparse(website)
    domain = parsed_url.hostname or "unknown_domain"

    # Create a directory for robots.txt files if it doesn't exist
    os.makedirs("robots_files", exist_ok=True)

    # Define the file path
    file_path = os.path.join("robots_files", f"{domain}_robots.txt")

    # Write the content to the file
    with open(file_path, "w") as file:
        file.write(content)

    return f"robots.txt file has been downloaded and saved to: {file_path}\n"

def check_website_vulnerability(website):
    results = []
    parsed_url = urlparse(website)

    # Ensure the website URL includes a scheme
    if not parsed_url.scheme:
        website = f"https://{website}"
        parsed_url = urlparse(website)

    hostname = parsed_url.hostname

    # Only check SSL/TLS if the website uses HTTPS
    if parsed_url.scheme == "https" and hostname:
        results.append(check_ssl_certificate(hostname))
    elif parsed_url.scheme == "http":
        results.append(f"{website} is using HTTP, so SSL/TLS check is skipped.\n")

    # Test for common web application vulnerabilities
    try:
        # WordPress brute force
        response = req.get(f"{website}/wp-login.php")
        if response.status_code == 200:
            results.append(f"{website} may be vulnerable to WordPress brute force attacks\n")

        # phpMyAdmin installation
        response = req.get(f"{website}/phpmyadmin")
        if response.status_code == 200:
            results.append(f"{website} may have phpMyAdmin installed and accessible\n")

        # SQL injection
        response = req.get(f"{website}/?id=1' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -")
        if "SQL error" in response.text:
            results.append(f"{website} may be vulnerable to SQL injection attacks\n")

        # Directory listing
        response = req.get(f"{website}/?dir=/")
        if "Index of" in response.text:
            results.append(f"{website} may be vulnerable to directory listing attacks\n")

        # Cross-site scripting (XSS)
        response = req.get(f"{website}?name=<script>alert('XSS')</script>")
        if "<script>" in response.text:
            results.append(f"{website} may be vulnerable to cross-site scripting attacks\n")

        # Remote file inclusion (RFI)
        response = req.get(f"{website}/?page=http://example.com")
        if "example.com" in response.text:
            results.append(f"{website} may be vulnerable to remote file inclusion attacks\n")

        # OS command injection
        response = req.get(f"{website}/?cmd=ls")
        if "ls" in response.text:
            results.append(f"{website} may be vulnerable to OS command injection attacks\n")

        # Session protection
        try:
            session_id_1 = req.get(f"{website}").cookies["session_id"]
            response = req.get(f"{website}?newsession=true")
            session_id_2 = req.get(f"{website}").cookies["session_id"]
            if session_id_1 == session_id_2:
                results.append(f"{website} may not be properly protecting user sessions\n")
        except KeyError:
            results.append("Session protection check failed\n")

        # Robots.txt download
        response = req.get(f"{website}/robots.txt")
        if response.status_code == 200:
            results.append(download_robots_txt(website, response.text))

        # User enumeration
        response = req.get(f"{website}/?author=1")
        if "author" in response.text:
            results.append(f"{website} may be vulnerable to user enumeration attacks\n")

        # File upload
        try:
            with open("test.txt", "rb") as file:
                files = {"file": file}
                response = req.post(f"{website}/upload.php", files=files)
                if "File uploaded successfully" in response.text:
                    results.append(f"{website} may be vulnerable to file upload attacks\n")
        except KeyError:
            results.append("File upload check failed\n")

        # Additional Vulnerabilities
        # 1. Server Information Disclosure
        response = req.get(f"{website}/server-status")
        if response.status_code == 200:
            results.append(f"{website} may be disclosing server status information\n")

        # 2. Vulnerable Directories
        response = req.get(f"{website}/admin")
        if response.status_code == 200:
            results.append(f"{website} may have an exposed admin directory\n")

        # 3. Backup Files
        response = req.get(f"{website}/backup.zip")
        if response.status_code == 200:
            results.append(f"{website} may have backup files exposed\n")

        # 4. HTTP Methods
        response = req.options(f"{website}")
        if "OPTIONS" in response.headers.get("Allow", ""):
            results.append(f"{website} supports HTTP OPTIONS method which may disclose sensitive information\n")

        # 5. Open Redirect
        response = req.get(f"{website}/redirect?url=http://evil.com")
        if "evil.com" in response.text:
            results.append(f"{website} may be vulnerable to open redirect attacks\n")

        # 6. Insecure Deserialization
        response = req.get(f"{website}/deserialize?data=...")
        if "unexpected data" in response.text:
            results.append(f"{website} may be vulnerable to insecure deserialization attacks\n")

        # 7. HTTP Header Injection
        response = req.get(f"{website}/header-injection")
        if "Injected Header" in response.text:
            results.append(f"{website} may be vulnerable to HTTP header injection attacks\n")

        # 8. Missing Security Headers
        headers = req.get(f"{website}").headers
        missing_headers = []
        for header in ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]:
            if header not in headers:
                missing_headers.append(header)
        if missing_headers:
            results.append(f"{website} is missing security headers: {', '.join(missing_headers)}\n")

        # 9. Weak Password Policy
        response = req.get(f"{website}/change-password")
        if "password" in response.text and "8 characters" not in response.text:
            results.append(f"{website} may have a weak password policy\n")

        # 10. Rate Limiting
        response = req.get(f"{website}/login", params={"user": "test", "password": "test"})
        if "rate limit" in response.text.lower():
            results.append(f"{website} has rate limiting which may prevent brute force attacks\n")

    except Exception as e:
        results.append(f"Error: {str(e)}\n")

    return "\n".join(results)

def main(page: Page):
    page.title = "Network Hacking System"
    page.window_height = 630
    page.window_width = 390
    page.window_top = 70
    page.bgcolor = 'white'
    page.window_left = 960
    page.scroll = 'auto'
    page.theme_mode = ThemeMode.LIGHT

    ping_textarea = TextField(
        multiline=True,
        border=InputBorder.NONE,
        width=300,
        height=260,
        hint_text="Ping Results...",
        color=colors.BLACK,
    )

    portscan_textarea = TextField(
        multiline=True,
        border=InputBorder.NONE,
        width=300,
        height=260,
        hint_text="Port Scan Results...",
        color=colors.BLACK,
    )
    
    websitescan_textarea = TextField(
        multiline=True,
        border=InputBorder.NONE,
        width=300,
        height=260,
        hint_text="Website Scan Results...",
        color=colors.BLACK,
    )

    ipaddress = TextField(
        width=300,
        height=37,
        label="IP Address",
        color=colors.BLACK,
    )
    
    webAddress = TextField(
        width=300,
        height=43,
        label="Website Address",
        color=colors.BLACK,
    )

    packet_count = TextField(
        width=300,
        height=37,
        label="Number of Packets",
        color=colors.BLACK,
    )

    start_port = TextField(
        width=145,
        height=37,
        label="Start Port",
        color=colors.BLACK,
    )

    end_port = TextField(
        width=145,
        height=37,
        label="End Port",
        color=colors.BLACK,
    )

    def send_packet(e):
        target_ip = ipaddress.value
        count = packet_count.value

        if target_ip and count.isdigit():
            count = int(count)
            send_ping(target_ip, count, ping_textarea)
        else:
            if not target_ip:
                ping_textarea.value += "Please enter a valid IP address.\n"
            if not count.isdigit():
                ping_textarea.value += "Please enter a valid number of packets.\n"
            ping_textarea.update()

    def start_port_scan(e):
        target_ip = ipaddress.value
        start = start_port.value
        end = end_port.value

        if target_ip and start.isdigit() and end.isdigit():
            start = int(start)
            end = int(end)
            scan_ports(target_ip, start, end, portscan_textarea)
        else:
            portscan_textarea.value += "Please enter valid IP address and port numbers.\n"
            portscan_textarea.update()

    def start_website_scan(e):
        target_website = webAddress.value
        if target_website:
            results = check_website_vulnerability(target_website)
            websitescan_textarea.value = results
            websitescan_textarea.update()
        else:
            websitescan_textarea.value += "Please enter a valid website address.\n"
            websitescan_textarea.update()

    def exit_app(e):
        page.window_close()

    def on_route_change(route):
        page.views.clear()

        if page.route == "/":
            page.views.append(
                View(
                    "/",
                    [
                        AppBar(
                            title=Text("Network Tracker", color=colors.WHITE),
                            bgcolor=colors.BLUE,
                        ),
                        Text("Welcome to our app", size=15, color='black', width=370, text_align='center'),
                        Row([
                            Image(src="assets/icos.png", width=280, height=280)
                        ], alignment=MainAxisAlignment.CENTER),
                        Text("\n"),
                        Row([
                            ElevatedButton(
                                icon=icons.WARNING,
                                text="Start Attack",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=lambda _: page.go("/sherlock")
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.EXIT_TO_APP,
                                text="Exit",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.RED, color='white'),
                                on_click=exit_app
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                            Text("\nDeveloped by [TK] Full Stack Developer", size=15, color='black', width=370, text_align='center'),
                        ], alignment=MainAxisAlignment.CENTER),
                    ],
                )
            )
            page.update()

        elif page.route == "/sherlock":
            page.views.append(
                View(
                    "/sherlock",
                    [
                        AppBar(
                            leading=IconButton(
                                icon=icons.ARROW_BACK,
                                icon_color=colors.WHITE,
                                on_click=lambda _: page.go("/")
                            ),
                            title=Text("Network Tracker", color=colors.WHITE),
                            bgcolor=colors.BLUE,
                        ),
                        Text("Send Ping Packets", size=15, color='black', width=370, text_align='center'),
                        Row([ ping_textarea ], alignment=MainAxisAlignment.CENTER),
                        Row([ ipaddress ], alignment=MainAxisAlignment.CENTER),
                        Row([ packet_count ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.WARNING,
                                text="Start Attack",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=send_packet
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.LAN,
                                text="Scan Port",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=lambda _: page.go("/scan")
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                            Text("\nDeveloped by [TK] Full Stack Developer", size=15, color='black', width=370, text_align='center'),
                        ], alignment=MainAxisAlignment.CENTER),
                    ],
                )
            )
            page.update()

        elif page.route == "/scan":
            page.views.append(
                View(
                    "/scan",
                    [
                        AppBar(
                            leading=IconButton(
                                icon=icons.ARROW_BACK,
                                icon_color=colors.WHITE,
                                on_click=lambda _: page.go("/")
                            ),
                            title=Text("Port Scanner", color=colors.WHITE),
                            bgcolor=colors.BLUE,
                        ),
                        Text("Scan Ports on a Target IP", size=15, color='black', width=370, text_align='center'),
                        Row([ portscan_textarea ], alignment=MainAxisAlignment.CENTER),
                        Row([ ipaddress ], alignment=MainAxisAlignment.CENTER),
                        Row([ start_port, end_port ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.LAN,
                                text="Start Port Scan",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=start_port_scan
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.WEB,
                                text="Start Website Scan",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=lambda _: page.go("/web")
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                            Text("\nDeveloped by [TK] Full Stack Developer", size=15, color='black', width=370, text_align='center'),
                        ], alignment=MainAxisAlignment.CENTER),
                    ],
                )
            )
            page.update()
            
        elif page.route == "/web":
            page.views.append(
                View(
                    "/web",
                    [
                        AppBar(
                            leading=IconButton(
                                icon=icons.ARROW_BACK,
                                icon_color=colors.WHITE,
                                on_click=lambda _: page.go("/")
                            ),
                            title=Text("Website Vulnerabilities", color=colors.WHITE),
                            bgcolor=colors.BLUE,
                        ),
                        Text("Scan Website Now", size=15, color='black', width=370, text_align='center'),
                        Row([ websitescan_textarea ], alignment=MainAxisAlignment.CENTER),
                        Row([ webAddress ], alignment=MainAxisAlignment.CENTER),
                        Row([
                             ElevatedButton(
                                icon=icons.WEB,
                                text="Start Website Scan",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.BLUE, color='white'),
                                on_click=start_website_scan
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                         Row([
                             ElevatedButton(
                                icon=icons.EXIT_TO_APP,
                                text="Exit",
                                width=300,
                                style=ButtonStyle(bgcolor=colors.RED, color='white'),
                                on_click=exit_app
                            ),
                        ], alignment=MainAxisAlignment.CENTER),
                        Row([
                            Text("\nDeveloped by [TK] Full Stack Developer", size=15, color='black', width=370, text_align='center'),
                        ], alignment=MainAxisAlignment.CENTER),
                    ],
                )
            )
            page.update()

    page.on_route_change = on_route_change
    page.go("/") 

app(target=main)
