import base64
import os
import json
import hashlib
import datetime
import random
import threading
import queue
import time
import colorama
from colorama import Fore, Style
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import tls_client
import websocket


# Initialize colorama for cross-platform colored terminal output
colorama.init(autoreset=True)


def update_title_stats(stats, total, processed=0):
    """Update the command window title with current statistics"""
    success_rate = (stats["success"] / processed * 100) if processed > 0 else 0
    title = f"Discord_Token_Changer_Processed_{processed}_of_{total}_Success_{stats['success']}_Invalid_{stats['invalid']}_Failed_{stats['failed']}_Rate_{success_rate:.1f}percent"
    # Set the console title
    os.system(f"title {title}")


def log(category, message, token=None, thread_id=None):
    """Clean logging function with timestamp and categories"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    # Build thread and token info if provided
    thread_info = f"thread [{thread_id}]" if thread_id else ""
    token_info = f"token [{token[:20]}...]" if token else ""
    
    # Combine components that are present
    components = [comp for comp in [thread_info, token_info] if comp]
    component_str = " | ".join(components)
    if component_str:
        component_str = " | " + component_str
    
    # Set colors based on category
    if category == "SUCCESS":
        category_color = Fore.LIGHTGREEN_EX
        message_color = Fore.WHITE
    elif category == "INVALID":
        category_color = Fore.LIGHTRED_EX
        message_color = Fore.WHITE
    elif category == "ERROR":
        return  # Don't print ERROR messages - they're handled internally
    elif category == "FAILED":
        category_color = Fore.LIGHTRED_EX
        message_color = Fore.WHITE
    elif category == "RETRY":
        category_color = Fore.LIGHTYELLOW_EX
        message_color = Fore.WHITE
    elif category == "STARTUP":
        category_color = Fore.LIGHTCYAN_EX
        message_color = Fore.LIGHTWHITE_EX
    elif category == "VERSION" or category == "TIME":
        category_color = Fore.LIGHTBLUE_EX
        message_color = Fore.LIGHTWHITE_EX
    elif category == "COMPLETE" or category == "OUTPUT":
        category_color = Fore.CYAN  # Changed from LIGHTMAGENTA_EX to CYAN
        message_color = Fore.LIGHTWHITE_EX
    elif category == "CONFIG":
        category_color = Fore.LIGHTBLUE_EX
        message_color = Fore.LIGHTWHITE_EX
    elif category == "PROXIES":
        category_color = Fore.WHITE  # Changed from default to WHITE for PROXIES
        message_color = Fore.WHITE
    elif category == "TOKENS":
        category_color = Fore.WHITE  # Changed from default to WHITE for TOKENS
        message_color = Fore.WHITE
    else:
        category_color = Fore.LIGHTYELLOW_EX
        message_color = Fore.WHITE
    
    # Use lock to ensure the entire line is printed without interruption
    with print_lock:
        print(f"{Fore.LIGHTBLACK_EX}{timestamp} »{Style.RESET_ALL} {category_color}{category} ●{Style.RESET_ALL} {message_color}{message}{Style.RESET_ALL}{component_str}", flush=True)

class Main:
    def __init__(self, token: str, proxy=None, thread_id=None) -> None:
        self.token = token
        self.proxy = proxy
        self.thread_id = thread_id
        
        # Initialize TLS client session with advanced fingerprinting prevention
        self.sess = tls_client.Session(
            client_identifier="chrome_120",
            random_tls_extension_order=True
        )
        
        # Set proxy if provided
        if proxy:
            proxy_parts = proxy.split('@')
            if len(proxy_parts) == 2:
                auth, addr = proxy_parts
                user, password = auth.split(':')
                host, port = addr.split(':')
                proxy_dict = {
                    "http": f"http://{user}:{password}@{host}:{port}",
                    "https": f"http://{user}:{password}@{host}:{port}"
                }
            else:
                host, port = proxy.split(':')
                proxy_dict = {
                    "http": f"http://{host}:{port}",
                    "https": f"http://{host}:{port}"
                }
            self.sess.proxies = proxy_dict
            
        # Set Discord headers
        self.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTIwLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjI1MDgzMiwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0='
        }
        
        for header, value in self.headers.items():
            self.sess.headers[header] = value
            
        self.ws_url = "wss://remote-auth-gateway.discord.gg/?v=2"
    
    def create_kp(self) -> tuple:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        return priv.public_key(), priv
    
    def encode_pk(self, pub) -> str:
        return base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')
    
    def proc_nonce(self, nonce_data: str, priv) -> str:
        data = json.loads(nonce_data)
        enc_nonce = base64.b64decode(data["encrypted_nonce"])
        
        dec_nonce = priv.decrypt(
            enc_nonce,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return json.dumps({
            "op": "nonce_proof",
            "proof": base64.urlsafe_b64encode(hashlib.sha256(dec_nonce).digest()).rstrip(b"=").decode(),
        })
    
    def decrypt(self, enc_data: str, priv) -> bytes:
        if not enc_data:
            return None
        
        payload = base64.b64decode(enc_data)
        return priv.decrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def handshake(self, fp: str) -> None:
        r = self.sess.post(
            "https://discord.com/api/v9/users/@me/remote-auth", 
            json={'fingerprint': fp}
        ).json()
        
        token = r.get('handshake_token')
        if token:
            self.sess.post(
                "https://discord.com/api/v9/users/@me/remote-auth/finish", 
                json={'handshake_token': token}
            )
    
    def is_valid_token(self) -> bool:
        """Check if the token is actually valid by making a test request to Discord API"""
        try:
            # Make a simple request to Discord API
            r = self.sess.get('https://discord.com/api/v9/users/@me')
            
            # If we get a 200 OK, the token is valid
            return r.status_code == 200
        except Exception:
            return False
    
    def logout(self, token: str) -> bool:
        self.sess.headers['authorization'] = token
        
        r = self.sess.post(
            'https://discord.com/api/v9/auth/logout',
            json={'provider': None, 'voip_provider': None}
        )
        return r.status_code == 204
    
    def clone(self) -> str:
        try:
            log("PROCESS", "Starting token process", self.token, self.thread_id)
                
            ws_options = {
                "header": [
                    f"Authorization: {self.token}",
                    "Origin: https://discord.com"
                ],
                "timeout": 10  # 10 second timeout
            }
            
            # Add proxy to websocket if available
            if self.proxy:
                proxy_parts = self.proxy.split('@')
                if len(proxy_parts) == 2:
                    auth, addr = proxy_parts
                    host, port = addr.split(':')
                    ws_options["http_proxy_host"] = host
                    ws_options["http_proxy_port"] = int(port)
                    if auth:
                        user, password = auth.split(':')
                        ws_options["http_proxy_auth"] = (user, password)
            
            try:
                ws = websocket.create_connection(
                    self.ws_url,
                    **ws_options
                )
            
                ws.recv()
                
                pub, priv = self.create_kp()
                enc_key = self.encode_pk(pub)
                
                ws.send(json.dumps({"op": "init", "encoded_public_key": enc_key}))
                
                nonce = ws.recv()
                proof = self.proc_nonce(nonce, priv)
                ws.send(proof)
                
                fp_data = json.loads(ws.recv())
                fp = fp_data.get("fingerprint")
                if not fp:
                    return None
                
                self.handshake(fp)
                
                user_data = json.loads(ws.recv())
                enc_user = user_data.get("encrypted_user_payload")
                if enc_user:
                    self.decrypt(enc_user, priv)
                
                ticket_data = json.loads(ws.recv())
                ticket = ticket_data.get("ticket")
                if not ticket:
                    return None
                
                login_r = self.sess.post(
                    "https://discord.com/api/v9/users/@me/remote-auth/login", 
                    json={"ticket": ticket}
                )
                
                r_data = login_r.json()
                enc_token = r_data.get("encrypted_token")
                if not enc_token:
                    return None
                
                ws.close()
                
                new_token = self.decrypt(enc_token, priv)
                if not new_token:
                    return None
                
                decoded_token = new_token.decode('utf-8')
                log("SUCCESS", "Token changed successfully", self.token, self.thread_id)
                
                return decoded_token
            except (websocket.WebSocketTimeoutException, websocket.WebSocketConnectionClosedException) as e:
                return None
            
        except Exception:
            return None


def extract_token_from_line(line):
    """Extract token from different input formats"""
    if line.count(':') >= 2:
        # Email:pass:token format
        parts = line.split(':')
        return ':'.join(parts[2:]), line.split(':')[0] + ':' + line.split(':')[1] + ':'
    else:
        # Token only format
        return line, ""


def load_proxies(proxy_file):
    """Load proxies from file"""
    if not os.path.exists(proxy_file):
        with open(proxy_file, "w") as f:
            f.write("# Place your proxies here, one per line in format user:pass@ip:port\n")
        log("INFO", f"Created {proxy_file}. Please add your proxies to this file if needed.")
        return []
    
    with open(proxy_file, "r") as f:
        proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    return proxies


def load_config():
    """Load configuration from config.json if it exists, otherwise create default config"""
    config_file = "config.json"
    default_config = {
        "proxies": True,
        "threads": 10
    }
    
    # Check if config file exists
    if not os.path.exists(config_file):
        # Create default config file
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)
        log("INFO", f"Created default {config_file}. You can modify it to customize settings.")
        return default_config
    
    # Load existing config
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        
        # Validate config values
        if "proxies" not in config or not isinstance(config["proxies"], bool):
            config["proxies"] = default_config["proxies"]
            log("CONFIG", "Invalid 'proxies' value in config.json, using default: True")
            
        if "threads" not in config or not isinstance(config["threads"], int) or config["threads"] < 1:
            config["threads"] = default_config["threads"]
            log("CONFIG", "Invalid 'threads' value in config.json, using default: 10")
        
        return config
    except Exception as e:
        log("ERROR", f"Error loading config.json: {str(e)}. Using default settings.")
        return default_config


def print_ascii_banner():
    banner = """

        ▄▄▄█████▓ ▒█████   ██ ▄█▀▓█████  ███▄    █     ▄████▄   ██░ ██  ▄▄▄       ███▄    █   ▄████ ▓█████  ██▀███  
        ▓  ██▒ ▓▒▒██▒  ██▒ ██▄█▒ ▓█   ▀  ██ ▀█   █    ▒██▀ ▀█  ▓██░ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
        ▒ ▓██░ ▒░▒██░  ██▒▓███▄░ ▒███   ▓██  ▀█ ██▒   ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
        ░ ▓██▓ ░ ▒██   ██░▓██ █▄ ▒▓█  ▄ ▓██▒  ▐▌██▒   ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄  
        ▒██▒ ░ ░ ████▓▒░▒██▒ █▄░▒████▒▒██░   ▓██░   ▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░▒████▒░██▓ ▒██▒
        ▒ ░░   ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░░ ▒░ ░░ ▒░   ▒ ▒    ░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
            ░      ░ ▒ ▒░ ░ ░▒ ▒░ ░ ░  ░░ ░░   ░ ▒░     ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
        ░      ░ ░ ░ ▒  ░ ░░ ░    ░      ░   ░ ░    ░         ░  ░░ ░  ░   ▒      ░   ░ ░ ░ ░   ░    ░     ░░   ░ 
                    ░ ░  ░  ░      ░  ░         ░    ░ ░       ░  ░  ░      ░  ░         ░       ░    ░  ░   ░     
                                                    ░                                                             
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    log("STARTUP", "Discord Token Changer - Multi Threaded")
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")    
    # Set initial title
    os.system("title Discord_Token_Changer_Starting")


def worker(thread_id, task_queue, output_file, lock, stats, proxies, total_tokens):
    """Worker function that processes tokens from the task queue"""
    while not task_queue.empty():
        try:
            # Get a task from the queue
            token_data = task_queue.get(timeout=1)
            token, prefix, original_line, index, total = token_data
            
            # Try to process the token with different proxies if needed
            max_retries = 5 if proxies else 1
            retry_count = 0
            success = False
            
            while retry_count < max_retries and not success:
                try:
                    # Select a proxy if available
                    proxy = None
                    if proxies:
                        proxy = random.choice(proxies)
                    
                    # Process the token
                    dc = Main(token, proxy, thread_id)
                    new_token = dc.clone()
                    
                    if new_token and dc.logout(token):
                        # Format the output based on the input format
                        if prefix:
                            # This was email:pass:token format
                            output_line = f"{prefix}{new_token}"
                        else:
                            # This was token-only format
                            output_line = new_token
                        
                        # Save to file in real-time (with thread lock to prevent race conditions)
                        with lock:
                            # Write immediately to the file to ensure it's saved even if program is force-closed
                            with open(output_file, "a") as f:
                                f.write(f"{output_line}\n")
                                # Flush file to ensure it's written to disk
                                f.flush()
                                # Force OS to write data to physical storage
                                os.fsync(f.fileno())
                                
                            stats["success"] += 1
                            # Update counter and title
                            stats["processed"] += 1
                            update_title_stats(stats, total_tokens, stats["processed"])
                        
                        success = True
                    else:
                        # Check if token is invalid by making API request
                        if hasattr(dc, 'sess'):  # Make sure we have a session object
                            # Check if token is valid before reporting as failure
                            if not dc.is_valid_token():
                                with lock:
                                    stats["invalid"] += 1
                                    # Update counter and title
                                    stats["processed"] += 1
                                    update_title_stats(stats, total_tokens, stats["processed"])
                                    log("INVALID", f"Token is invalid", token, thread_id)
                                success = True  # Mark as processed to avoid retries
                            # Only log failure if it's the last retry or we have no proxies
                            elif retry_count == max_retries - 1 or not proxies:
                                with lock:
                                    stats["failed"] += 1
                                    # Update counter and title
                                    stats["processed"] += 1
                                    update_title_stats(stats, total_tokens, stats["processed"])
                                    log("FAILED", f"Token change failed", token, thread_id)
                        else:
                            # If the session wasn't created, just log as a regular failure
                            if retry_count == max_retries - 1 or not proxies:
                                with lock:
                                    stats["failed"] += 1
                                    # Update counter and title
                                    stats["processed"] += 1
                                    update_title_stats(stats, total_tokens, stats["processed"])
                                    log("FAILED", f"Token {index+1}/{total} change failed", token, thread_id)
                
                except Exception as e:
                    # If we have proxies, try another one
                    if proxies and retry_count < max_retries - 1:
                        with lock:
                            log("RETRY", f"Proxy timeout/error, trying another proxy (attempt {retry_count+1}/{max_retries})", token, thread_id)
                    elif retry_count == max_retries - 1:
                        with lock:
                            stats["failed"] += 1
                            # Update counter and title
                            stats["processed"] += 1
                            update_title_stats(stats, total_tokens, stats["processed"])
                            log("FAILED", f"Token {index+1}/{total} change failed after {max_retries} proxy attempts", token, thread_id)
                
                retry_count += 1
                
                # Short delay between retries
                if not success and retry_count < max_retries:
                    time.sleep(random.uniform(1.0, 2.0))
            
            # Mark the task as done
            task_queue.task_done()
            
            # Add a small delay to prevent rate limiting
            time.sleep(random.uniform(1.0, 2.0))
            
        except queue.Empty:
            break
        except Exception as e:
            with lock:
                stats["failed"] += 1
                # Update counter and title
                stats["processed"] += 1
                update_title_stats(stats, total_tokens, stats["processed"])
                log("ERROR", f"Unexpected error: {str(e)}", token if 'token' in locals() else None, thread_id)
            
            # Mark the task as done even if it failed
            if 'token_data' in locals():
                task_queue.task_done()


def process_tokens_from_file():
    # Create a global lock for printing
    global print_lock
    print_lock = threading.Lock()
    
    # Print the ASCII banner
    print_ascii_banner()
    
    # Load configuration from config.json
    config = load_config()
    thread_count = config["threads"]
    use_proxies = config["proxies"]
    
    log("CONFIG", f"Using configuration: Threads={thread_count}, Use Proxies={use_proxies}")
    
    # Create input directory if it doesn't exist
    os.makedirs("input", exist_ok=True)
    
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    # Create datetime-specific output directory
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    output_dir = os.path.join("output", current_date)
    os.makedirs(output_dir, exist_ok=True)
    
    input_file = "input/tokens.txt"
    proxy_file = "input/proxies.txt"
    output_file = os.path.join(output_dir, "changed-tokens.txt")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        with open(input_file, "w") as f:
            f.write("# Place your tokens here, one per line\n")
            f.write("# Supported formats: token or email:pass:token\n")
        log("INFO", f"Created {input_file}. Please add your tokens to this file and run the script again.")
        return
    
    # Load proxies only if enabled in config
    proxies = []
    if use_proxies:
        proxies = load_proxies(proxy_file)
        if proxies:
            log("PROXIES", f"Loaded {len(proxies)} proxies")
        else:
            log("PROXIES", "No proxies found. Will connect directly")
    else:
        log("PROXIES", "Proxies disabled in config.json")
    
    # Read tokens from file
    lines = []
    with open(input_file, "r") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    if not lines:
        log("ERROR", f"No tokens found in {input_file}. Please add your tokens and run the script again.")
        return
    
    # Extract tokens and formats
    token_data = []
    for line in lines:
        token, prefix = extract_token_from_line(line)
        token_data.append((token, prefix, line))
    
    log("TOKENS", f"Found {len(token_data)} tokens to process")
    print("")
    
    # Update title with initial stats
    update_title_stats({"success": 0, "failed": 0, "invalid": 0, "processed": 0}, len(token_data))
    
    # Create output file (empty file - no header)
    with open(output_file, "w") as f:
        pass  # Just create an empty file
    
    # Create a queue for the worker threads
    task_queue = queue.Queue()
    
    # Add tasks to the queue
    for i, (token, prefix, original_line) in enumerate(token_data):
        task_queue.put((token, prefix, original_line, i, len(token_data)))
    
    # Create a thread lock for file access and printing
    lock = threading.Lock()
    
    # Track statistics
    stats = {"success": 0, "failed": 0, "invalid": 0, "processed": 0}
    
    # Adjust thread count if we have fewer tokens
    thread_count = min(thread_count, len(token_data))
    
    # Create and start worker threads
    threads = []
    for i in range(thread_count):
        thread = threading.Thread(
            target=worker,
            args=(i+1, task_queue, output_file, lock, stats, proxies, len(token_data))
        )
        threads.append(thread)
        thread.start()
    
    # Wait for the tasks to complete with keyboard interrupt handling
    try:
        # Wait without showing progress
        while not task_queue.empty():
            time.sleep(1)
            # Update the title bar every second with latest stats
            with lock:
                update_title_stats(stats, len(token_data), stats["processed"])
    except KeyboardInterrupt:
        log("INTERRUPT", "Process interrupted by user. Waiting for threads to complete...")
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Final update of the title bar
    update_title_stats(stats, len(token_data), stats["processed"])
    
    log("COMPLETE", f"Process finished. Changed: {stats['success']}, Failed: {stats['failed']}, Invalid: {stats['invalid']}, Total: {len(token_data)}")
    log("OUTPUT", f"Results saved to {output_file}")
    
    # Set final title
    elapsed_time = time.time() - start_time
    os.system(f"title Discord_Token_Changer_FINISHED_Success_{stats['success']}_Time_{int(elapsed_time)}s")


if __name__ == "__main__":
    # Track start time for duration calculation
    start_time = time.time()
    
    # Use process_tokens_from_file without parameters (config is loaded from config.json)
    process_tokens_from_file()