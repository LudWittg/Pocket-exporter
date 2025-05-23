#!/usr/bin/env python3
"""
Pocket API Exporter v0.1
Secure, reliable export of Pocket items with comprehensive error handling,
encrypted token storage, retry logic, and streaming processing.

Usage:
    python pocket_exporter.py --help
    python pocket_exporter.py --export json --output backup.json
    python pocket_exporter.py --export csv --incremental
"""

import requests
import json
import csv
import time
import os
import hashlib
import secrets
import ssl
import logging
import signal
import sys
import argparse
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Dict, List, Optional, Union, Iterator, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import tempfile
import shutil

# Third-party imports (install with: pip install cryptography keyring)
try:
    import keyring
    from cryptography.fernet import Fernet
    SECURE_STORAGE = True
except ImportError:
    SECURE_STORAGE = False
    print("Warning: Install 'keyring' and 'cryptography' for secure token storage")

# For API limits, see: https://getpocket.com/developer/docs/rate-limits
API_LIMITS = {
    'DAILY_MAX': 9500,
    'HOURLY_MAX': 300,
    'REQUESTS_PER_HOUR': 320,
    'REQUESTS_PER_DAY': 10000
}

@dataclass
class ExportConfig:
    """Configuration for export operations"""
    batch_size: int = 500
    max_retries: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    timeout: int = 30
    oauth_timeout: int = 300
    checkpoint_interval: int = 100
    daily_limit: int = API_LIMITS['DAILY_MAX']
    hourly_limit: int = API_LIMITS['HOURLY_MAX']
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ExportConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            return cls(**{k: v for k, v in config_data.items() if k in cls.__annotations__})
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.debug(f"Config file not found or invalid: {e}")
            return cls()

class SecureTokenStorage:
    """Secure token storage using system keyring with encrypted fallback"""
    
    def __init__(self, consumer_key: str):
        self.service_name = "pocket_exporter"
        self.username = f"user_{hashlib.sha256(consumer_key.encode()).hexdigest()[:16]}"
        self.encryption_key = self._get_or_create_key()
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        if SECURE_STORAGE:
            try:
                key = keyring.get_password(self.service_name, f"{self.username}_key")
                if key:
                    return key.encode()
            except Exception as e:
                logging.debug(f"Keyring access failed: {e}")
        
        # Fallback: store key in file (less secure but functional)
        key_file = Path.home() / f".pocket_key_{self.username}"
        if key_file.exists():
            return key_file.read_bytes()
        
        key = Fernet.generate_key()
        try:
            if SECURE_STORAGE:
                keyring.set_password(self.service_name, f"{self.username}_key", key.decode())
                logging.info("Encryption key stored in system keyring")
            else:
                key_file.write_bytes(key)
                os.chmod(key_file, 0o600)  # Restrict permissions
                logging.warning(f"Encryption key stored in file: {key_file} (install 'keyring' for more secure storage)")
        except Exception as e:
            logging.warning(f"Could not save encryption key: {e}")
        
        return key
    
    def save_token(self, token: str) -> bool:
        """Save encrypted token"""
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_token = fernet.encrypt(token.encode())
            
            if SECURE_STORAGE:
                keyring.set_password(self.service_name, self.username, encrypted_token.decode())
                logging.info("Access token saved to system keyring")
            else:
                token_file = Path.home() / f".pocket_token_{self.username}"
                token_file.write_bytes(encrypted_token)
                os.chmod(token_file, 0o600)
                logging.warning(f"Access token saved to encrypted file: {token_file}")
            
            return True
        except Exception as e:
            logging.error(f"Failed to save token: {e}")
            return False
    
    def load_token(self) -> Optional[str]:
        """Load and decrypt token"""
        try:
            encrypted_token = None
            
            if SECURE_STORAGE:
                encrypted_token = keyring.get_password(self.service_name, self.username)
                if encrypted_token:
                    encrypted_token = encrypted_token.encode()
            
            if not encrypted_token:
                token_file = Path.home() / f".pocket_token_{self.username}"
                if token_file.exists():
                    encrypted_token = token_file.read_bytes()
            
            if encrypted_token:
                fernet = Fernet(self.encryption_key)
                return fernet.decrypt(encrypted_token).decode()
                
        except Exception as e:
            logging.error(f"Failed to load token: {e}")
        
        return None

class HTTPCallbackHandler(BaseHTTPRequestHandler):
    """HTTP OAuth callback handler - POCKET-SPECIFIC VERSION"""
    
    def log_message(self, format, *args) -> None:
        """Suppress default HTTP server logging"""
        pass
    
    def do_GET(self) -> None:
        """Handle OAuth callback - Pocket-specific implementation"""
        try:
            logging.debug(f"Received callback: {self.path}")
            
            if self.path.startswith('/auth'):
                parsed_url = urlparse(self.path)
                query = parse_qs(parsed_url.query)
                
                code = query.get('code', [None])[0]    # Pocket never sends this
                state = query.get('state', [None])[0]  # Pocket never sends this either
                
                logging.debug(f"Received code: {code}")
                logging.debug(f"Received state: {state}")
                
                # ---------- POCKET-SPECIFIC SHORT-CIRCUIT ----------
                # Pocket calls /auth with **no query parameters**.
                # Any request that gets here therefore means "user approved".
                if code is None and state is None:
                    logging.info("Pocket callback received – proceeding with stored request_token")
                    self.server.auth_code = True  # value itself is irrelevant
                    self._send_success_response()
                    return
                
                # Handle other OAuth providers that do send parameters
                if code:
                    logging.info("Authorization code received from OAuth provider")
                    self.server.auth_code = code
                    self._send_success_response()
                    return
                
                # If we get here, something unexpected happened
                self._send_error_response("No authorization received")
                return
            else:
                self._send_error_response("Not found", status=404)
                
        except Exception as e:
            logging.error(f"OAuth callback error: {e}")
            self._send_error_response("Internal error")
    
    def _send_success_response(self) -> None:
        """Send success page"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        html = """
        <html><head><title>Authorization Success</title>
        <style>body{font-family:sans-serif;text-align:center;margin:50px;color:#333;}</style></head>
        <body><h1>✓ Authorization Successful</h1>
        <p>You can safely close this window and return to the application.</p></body></html>
        """
        self.wfile.write(html.encode())
    
    def _send_error_response(self, message: str, status: int = 400) -> None:
        """Send error page"""
        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = f"""
        <html><head><title>OAuth Error</title></head>
        <body>
        <h1>Authorization Error</h1>
        <p>{message}</p>
        <p>Please close this window and try again.</p>
        <p>If this problem persists, try running with --log-level DEBUG for more information.</p>
        </body></html>
        """
        self.wfile.write(html.encode())

class RateLimiter:
    """Intelligent rate limiter with exponential backoff"""
    
    def __init__(self, config: ExportConfig):
        self.config = config
        self.last_request_time = 0
        self.consecutive_errors = 0
        self.daily_requests = 0
        self.hourly_requests = 0
        self.day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        self.hour_start = datetime.now().replace(minute=0, second=0, microsecond=0)
    
    def wait_if_needed(self) -> None:
        """Wait if rate limiting is needed"""
        now = datetime.now()
        
        # Reset counters
        if now.date() > self.day_start.date():
            self.daily_requests = 0
            self.day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        if now.hour > self.hour_start.hour:
            self.hourly_requests = 0
            self.hour_start = now.replace(minute=0, second=0, microsecond=0)
        
        # Check daily limit
        if self.daily_requests >= self.config.daily_limit:
            sleep_until = self.day_start + timedelta(days=1)
            sleep_seconds = max(0, (sleep_until - now).total_seconds())
            if sleep_seconds > 0:
                logging.warning(f"Daily limit reached, sleeping {sleep_seconds:.0f}s")
                time.sleep(min(sleep_seconds, 3600))  # Max 1 hour sleep
        
        # Check hourly limit
        if self.hourly_requests >= self.config.hourly_limit:
            sleep_until = self.hour_start + timedelta(hours=1)
            sleep_seconds = max(0, (sleep_until - now).total_seconds())
            if sleep_seconds > 0:
                logging.warning(f"Hourly limit reached, sleeping {sleep_seconds:.0f}s")
                time.sleep(min(sleep_seconds, 300))  # Max 5 minute sleep
        
        # Basic rate limiting with exponential backoff for errors
        elapsed = time.time() - self.last_request_time
        min_interval = self.config.base_delay * (1.5 ** min(self.consecutive_errors, 10))
        min_interval = min(min_interval, self.config.max_delay)
        
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        
        self.last_request_time = time.time()
        self.daily_requests += 1
        self.hourly_requests += 1
    
    def on_success(self) -> None:
        """Reset error counter on successful request"""
        self.consecutive_errors = 0
    
    def on_error(self) -> None:
        """Increment error counter"""
        self.consecutive_errors += 1

class CheckpointManager:
    """Manages export checkpoints for resumable operations"""
    
    def __init__(self, export_type: str, consumer_key: str):
        self.checkpoint_dir = Path.home() / ".pocket_checkpoints"
        self.checkpoint_dir.mkdir(exist_ok=True)
        
        checkpoint_id = hashlib.sha256(f"{export_type}_{consumer_key}".encode()).hexdigest()[:16]
        self.checkpoint_file = self.checkpoint_dir / f"checkpoint_{checkpoint_id}.json"
        self.temp_file = self.checkpoint_file.with_suffix('.tmp')
    
    def save_checkpoint(self, data: Dict):
        """Save checkpoint data atomically"""
        try:
            with open(self.temp_file, 'w') as f:
                json.dump(data, f)
            shutil.move(str(self.temp_file), str(self.checkpoint_file))
        except Exception as e:
            logging.error(f"Failed to save checkpoint: {e}")
    
    def load_checkpoint(self) -> Optional[Dict]:
        """Load checkpoint data"""
        try:
            if self.checkpoint_file.exists():
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load checkpoint: {e}")
        return None
    
    def clear_checkpoint(self):
        """Remove checkpoint file"""
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
        except Exception as e:
            logging.error(f"Failed to clear checkpoint: {e}")

class PocketExporter:
    """Pocket API exporter"""
    
    def __init__(self, consumer_key: str, config: Optional[ExportConfig] = None):
        self.consumer_key = consumer_key
        self.config = config or ExportConfig()
        self.access_token: Optional[str] = None
        self.base_url = "https://getpocket.com/v3"
        self.auth_url = "https://getpocket.com/auth"
        self.redirect_uri = "http://localhost:8080/auth"
        
        self.token_storage = SecureTokenStorage(consumer_key)
        self.rate_limiter = RateLimiter(self.config)
        self.session = requests.Session()
        self.session.timeout = self.config.timeout
        
        # Graceful shutdown handling
        self._shutdown_requested = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown"""
        logging.info("Shutdown requested, finishing current operation...")
        self._shutdown_requested = True
    
    def _check_shutdown(self):
        """Check if shutdown was requested"""
        if self._shutdown_requested:
            logging.info("Shutting down gracefully...")
            sys.exit(0)
    
    def _make_request_with_retry(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with exponential backoff retry"""
        for attempt in range(self.config.max_retries):
            self._check_shutdown()
            self.rate_limiter.wait_if_needed()
            
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logging.warning(f"Rate limited, waiting {retry_after}s")
                    time.sleep(min(retry_after, 300))  # Max 5 minute wait
                    self.rate_limiter.on_error()
                    continue
                
                # NEW: Don't retry on fatal 4xx client errors
                if 400 <= response.status_code < 500:
                    logging.error(f"Pocket returned {response.status_code}: {response.text}")
                    return None
                
                if response.status_code in (500, 502, 503, 504):
                    # Server errors - retry with backoff
                    delay = self.config.base_delay * (2 ** attempt)
                    delay = min(delay, self.config.max_delay)
                    logging.warning(f"Server error {response.status_code}, retrying in {delay}s")
                    time.sleep(delay)
                    self.rate_limiter.on_error()
                    continue
                
                response.raise_for_status()
                self.rate_limiter.on_success()
                return response
                
            except requests.exceptions.RequestException as e:
                delay = self.config.base_delay * (2 ** attempt)
                delay = min(delay, self.config.max_delay)
                logging.warning(f"Request failed (attempt {attempt + 1}): {e}")
                
                if attempt < self.config.max_retries - 1:
                    logging.info(f"Retrying in {delay}s...")
                    time.sleep(delay)
                    self.rate_limiter.on_error()
                else:
                    logging.error(f"Request failed after {self.config.max_retries} attempts")
                    return None
        
        return None
    
    def authenticate(self) -> bool:
        """OAuth2 authentication for Pocket API"""
        if self.access_token:
            return True
        
        # Try loading saved token
        token = self.token_storage.load_token()
        if token:
            self.access_token = token
            logging.info("Loaded saved authentication token")
            return True
        
        logging.info("Starting OAuth authentication...")
        
        request_token = self._get_request_token()
        if not request_token:
            return False
        
        # User authorization (no state parameter needed)
        logging.info("Opening browser for authorization...")
        
        # Start HTTP server for callback BEFORE opening browser
        if not self._handle_oauth_callback(request_token):
            return False
        
        access_token = self._get_access_token(request_token)
        if not access_token:
            return False
        
        self.access_token = access_token
        
        if self.token_storage.save_token(access_token):
            logging.info("Authentication successful and token saved")
        else:
            logging.warning("Authentication successful but token save failed")
        
        return True
    
    def _get_request_token(self) -> Optional[str]:
        """Obtain a temporary request-token from Pocket"""
        url = f"{self.base_url}/oauth/request"
        
        payload = {
            "consumer_key": self.consumer_key,
            "redirect_uri": self.redirect_uri
        }
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Accept": "application/json"
        }
        
        # Ask for JSON and send JSON
        response = self._make_request_with_retry("POST", url, headers=headers, json=payload)
        if not response:
            return None
        
        # Pocket may still fall back to form-style if headers are absent;
        # handle both just in case.
        try:
            if response.headers.get("Content-Type", "").startswith("application/json"):
                return response.json().get("code")
            else:
                return parse_qs(response.text).get("code", [None])[0]
        except Exception as e:
            logging.error(f"Failed to parse request token response: {e}")
            logging.debug(f"Response content: {response.text}")
            logging.debug(f"Response headers: {response.headers}")
            return None
    
    def _handle_oauth_callback(self, request_token: str) -> bool:
        """Handle OAuth callback with HTTP server for Pocket"""
        try:
            # Create HTTP server for OAuth callback
            server = HTTPServer(('localhost', 8080), HTTPCallbackHandler)
            server.auth_code = None
            
            logging.info(f"Starting HTTP server on localhost:8080...")
            
            # Give server a moment to fully initialize before opening browser
            time.sleep(0.5)
            
            # Create authorization URL (Pocket-specific - no state parameter)
            auth_url = f"{self.auth_url}/authorize?request_token={request_token}&redirect_uri={self.redirect_uri}"
            
            logging.debug(f"Opening browser with URL: {auth_url}")
            webbrowser.open(auth_url)
            
            logging.info(f"Waiting for authorization (timeout: {self.config.oauth_timeout}s)...")
            logging.info("Note: Using HTTP for localhost OAuth callback (standard practice)")
            
            start_time = time.time()
            request_count = 0
            
            while time.time() - start_time < self.config.oauth_timeout:
                try:
                    # Set a shorter timeout for each request to avoid hanging
                    server.timeout = 2.0
                    server.handle_request()
                    request_count += 1
                    
                    logging.debug(f"Handled request #{request_count}")
                    
                    if server.auth_code:
                        logging.info("Authorization code received successfully")
                        return True
                        
                    if self._shutdown_requested:
                        return False
                        
                except OSError as e:
                    # Handle timeout gracefully
                    if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                        continue
                    else:
                        logging.error(f"Server error: {e}")
                        break
            
            logging.error("OAuth timeout - no authorization received")
            logging.error("Please ensure you completed the authorization in your browser")
            return False
            
        except Exception as e:
            logging.error(f"OAuth callback error: {e}")
            return False
        finally:
            try:
                server.server_close()
            except:
                pass
    
    def _get_access_token(self, request_token: str) -> Optional[str]:
        """Convert the authorised request-token into an access-token"""
        url = f"{self.base_url}/oauth/authorize"
        
        payload = {
            "consumer_key": self.consumer_key,
            "code": request_token
        }
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Accept": "application/json"
        }
        
        # Use JSON body, not form-encoded data
        response = self._make_request_with_retry("POST", url, headers=headers, json=payload)
        if response:
            return response.json().get("access_token")
        return None
    
    def get_items_stream(self, since: Optional[int] = None) -> Iterator[Dict]:
        """Stream items with checkpointing and resumable export"""
        checkpoint_manager = CheckpointManager("export", self.consumer_key)
        
        # Try to resume from checkpoint
        checkpoint = checkpoint_manager.load_checkpoint()
        offset = checkpoint.get('offset', 0) if checkpoint else 0
        
        if checkpoint:
            logging.info(f"Resuming export from offset {offset}")
        
        total_fetched = offset
        consecutive_empty = 0
        
        try:
            # Stop after 3 empty batches
            while consecutive_empty < 3:
            #  Keeps asking Pocket for successive "pages" (`batch_size` items each)
            #  until one of these stop-conditions is met:
            #   – three pages in a row come back empty (`consecutive_empty < 3`)
            #   – the API returns fewer items than requested (end of list)
            #   – the user asks the program to shut down (SIGINT/TERM caught)
                self._check_shutdown()
                
                batch_data = self._get_items_batch(offset, self.config.batch_size, since)
                if not batch_data or 'list' not in batch_data:
                    consecutive_empty += 1
                    offset += self.config.batch_size
                    continue
                
                items = batch_data['list']
                if not items:
                    consecutive_empty += 1
                    offset += self.config.batch_size
                    continue
                
                consecutive_empty = 0
                batch_count = 0
                
                for item_id, item_data in items.items():
                    formatted_item = self._format_item_safe(item_data)
                    if formatted_item:
                        yield formatted_item
                        batch_count += 1
                        total_fetched += 1
                
                offset += len(items)
                
                # Save checkpoint periodically
                if total_fetched % self.config.checkpoint_interval == 0:
                    checkpoint_manager.save_checkpoint({
                        'offset': offset,
                        'total_fetched': total_fetched,
                        'timestamp': time.time()
                    })
                
                logging.info(f"Fetched {total_fetched} items...")
                
                # If we got fewer items than requested, we're likely done
                if len(items) < self.config.batch_size:
                    break
        
        finally:
            # Clear checkpoint on successful completion
            checkpoint_manager.clear_checkpoint()
    
    def _get_items_batch(self, offset: int, count: int, since: Optional[int] = None) -> Optional[Dict]:
        """Get a batch of items"""
        url = f"{self.base_url}/get"
        headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            'X-Accept': 'application/json'
        }
        
        data = {
            'consumer_key': self.consumer_key,
            'access_token': self.access_token,
            'detailType': 'complete',
            'state': 'all',
            'sort': 'newest',
            'count': count,
            'offset': offset
        }
        
        if since:
            data['since'] = since
        
        response = self._make_request_with_retry('POST', url, headers=headers, json=data)
        return response.json() if response else None
    
    def _format_item_safe(self, item_data: Dict) -> Optional[Dict]:
        """Safely format item data with error handling"""
        try:
            return {
                'item_id': item_data.get('item_id'),
                'resolved_id': item_data.get('resolved_id'),
                'given_url': item_data.get('given_url'),
                'resolved_url': item_data.get('resolved_url'),
                'given_title': item_data.get('given_title', ''),
                'resolved_title': item_data.get('resolved_title', ''),
                'excerpt': item_data.get('excerpt', ''),
                'is_article': item_data.get('is_article') == '1',
                'is_index': item_data.get('is_index') == '1',
                'has_video': item_data.get('has_video') == '1',
                'has_image': item_data.get('has_image') == '1',
                'word_count': self._safe_int(item_data.get('word_count')),
                'lang': item_data.get('lang'),
                'time_added': self._format_timestamp(item_data.get('time_added')),
                'time_updated': self._format_timestamp(item_data.get('time_updated')),
                'time_read': self._format_timestamp(item_data.get('time_read')),
                'time_favorited': self._format_timestamp(item_data.get('time_favorited')),
                'status': self._get_status(item_data.get('status')),
                'favorite': item_data.get('favorite') == '1',
                'tags': self._extract_tags(item_data.get('tags', {})),
                'authors': self._extract_authors(item_data.get('authors', {})),
                'images': self._extract_images(item_data.get('images', {})),
                'videos': self._extract_videos(item_data.get('videos', {}))
            }
        except Exception as e:
            logging.warning(f"Failed to format item {item_data.get('item_id', 'unknown')}: {e}")
            return None
    
    def _safe_int(self, value) -> int:
        """Safely convert to int"""
        try:
            return int(value) if value else 0
        except (ValueError, TypeError):
            return 0
    
    def _format_timestamp(self, timestamp) -> Optional[str]:
        """Convert timestamp to ISO format"""
        if timestamp and str(timestamp) != '0':
            try:
                return datetime.fromtimestamp(int(timestamp)).isoformat()
            except (ValueError, OSError, TypeError):
                return None
        return None
    
    def _get_status(self, status) -> str:
        """Convert status to readable format"""
        status_map = {'0': 'unread', '1': 'archived', '2': 'deleted'}
        return status_map.get(str(status), 'unknown')
    
    def _extract_tags(self, tags_data) -> List[str]:
        """Extract tags safely"""
        try:
            return list(tags_data.keys()) if tags_data else []
        except (AttributeError, TypeError):
            return []
    
    def _extract_authors(self, authors_data) -> List[str]:
        """Extract authors safely"""
        try:
            return [author.get('name', '') for author in authors_data.values()] if authors_data else []
        except (AttributeError, TypeError):
            return []
    
    def _extract_images(self, images_data) -> List[str]:
        """Extract images safely"""
        try:
            return [img.get('src', '') for img in images_data.values()] if images_data else []
        except (AttributeError, TypeError):
            return []
    
    def _extract_videos(self, videos_data) -> List[Dict[str, str]]:
        """Extract videos safely"""
        try:
            return [{'src': video.get('src', ''), 'type': video.get('type', '')} 
                   for video in videos_data.values()] if videos_data else []
        except (AttributeError, TypeError):
            return []
    
    @contextmanager
    def _atomic_file_write(self, filename: str):
        """Context manager for atomic file writes"""
        temp_file = f"{filename}.tmp"
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                yield f
            shutil.move(temp_file, filename)
        except Exception:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            raise
    
    def export_to_json_stream(self, filename: Optional[str] = None, incremental: bool = False) -> bool:
        """Export to JSON with streaming to handle large datasets"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_incremental" if incremental else ""
            filename = f"pocket_export{suffix}_{timestamp}.json"
        
        since = self._get_last_export_time() if incremental else None
        if incremental and since:
            logging.info(f"Incremental export since {datetime.fromtimestamp(since).isoformat()}")
        
        try:
            with self._atomic_file_write(filename) as f:
                f.write('{\n')
                f.write(f'  "export_date": "{datetime.now().isoformat()}",\n')
                f.write(f'  "export_type": "{"incremental" if incremental else "full"}",\n')
                f.write('  "items": [\n')
                
                item_count = 0
                for item in self.get_items_stream(since=since):
                    if item_count > 0:
                        f.write(',\n')
                    f.write('    ' + json.dumps(item, ensure_ascii=False))
                    item_count += 1
                    
                    if item_count % 100 == 0:
                        f.flush()  # Ensure data is written
                
                f.write(f'\n  ],\n')
                f.write(f'  "total_items": {item_count}\n')
                f.write('}\n')
            
            logging.info(f"Successfully exported {item_count} items to {filename}")
            self._update_last_export_time()
            return True
            
        except Exception as e:
            logging.error(f"Export failed: {e}")
            return False
    
    def export_to_csv_stream(self, filename: Optional[str] = None, incremental: bool = False) -> bool:
        """Export to CSV with streaming support"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_incremental" if incremental else ""
            filename = f"pocket_export{suffix}_{timestamp}.csv"
        
        since = self._get_last_export_time() if incremental else None
        if incremental and since:
            logging.info(f"Incremental CSV export since {datetime.fromtimestamp(since).isoformat()}")
        
        try:
            with self._atomic_file_write(filename) as f:
                writer = None
                item_count = 0
                
                for item in self.get_items_stream(since=since):
                    # Flatten item for CSV
                    flat_item = self._flatten_item_for_csv(item)
                    
                    # Initialize CSV writer with headers from first item
                    if writer is None:
                        writer = csv.DictWriter(f, fieldnames=flat_item.keys())
                        writer.writeheader()
                    
                    writer.writerow(flat_item)
                    item_count += 1
                    
                    if item_count % 100 == 0:
                        f.flush()
            
            logging.info(f"Successfully exported {item_count} items to {filename}")
            self._update_last_export_time()
            return True
            
        except Exception as e:
            logging.error(f"CSV export failed: {e}")
            return False
    
    def _flatten_item_for_csv(self, item: Dict) -> Dict:
        """Flatten complex item data for CSV export"""
        flat_item = item.copy()
        flat_item['tags'] = ', '.join(item['tags'])
        flat_item['authors'] = ', '.join(item['authors'])
        flat_item['images'] = ', '.join(item['images'])
        flat_item['videos'] = json.dumps(item['videos']) if item['videos'] else ''
        return flat_item
    
    def _get_last_export_time(self) -> Optional[int]:
        """Get last export timestamp"""
        meta_file = Path.home() / f".pocket_export_meta_{hashlib.sha256(self.consumer_key.encode()).hexdigest()[:16]}"
        try:
            with open(meta_file, 'r') as f:
                data = json.load(f)
                return data.get('last_export_time')
        except (FileNotFoundError, json.JSONDecodeError):
            return None
    
    def _update_last_export_time(self):
        """Update last export timestamp"""
        meta_file = Path.home() / f".pocket_export_meta_{hashlib.sha256(self.consumer_key.encode()).hexdigest()[:16]}"
        try:
            data = {'last_export_time': int(time.time())}
            with open(meta_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logging.warning(f"Could not update export metadata: {e}")

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.FileHandler('pocket_exporter.log'))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="Pocket API exporter with streaming support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --export json --output backup.json
  %(prog)s --export csv --incremental
  %(prog)s --consumer-key ABC123 --export json --quiet
  %(prog)s --config custom_config.json --export csv --output data.csv
  %(prog)s --export json --log-level DEBUG  # For troubleshooting OAuth issues
        """
    )

    # Authentication
    parser.add_argument(
        '--consumer-key', 
        type=str,
        help='Pocket API consumer key (or set POCKET_CONSUMER_KEY env var)'
    )

    # Export options
    parser.add_argument(
        '--export', 
        choices=['json', 'csv'],
        required=True,
        help='Export format'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output filename (auto-generated if not specified)'
    )

    parser.add_argument(
        '--incremental',
        action='store_true',
        help='Export only items modified since last export'
    )

    # Configuration
    parser.add_argument(
        '--config',
        type=str,
        default='pocket_config.json',
        help='Configuration file path (default: pocket_config.json)'
    )

    # Logging
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    parser.add_argument(
        '--log-file',
        type=str,
        help='Log file path (default: pocket_exporter.log)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress output (errors still shown)'
    )

    # Interactive mode
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive menu mode'
    )

    return parser

def run_cli_export(args, exporter: PocketExporter) -> bool:
    """Run export based on CLI arguments"""
    if args.export == 'json':
        return exporter.export_to_json_stream(args.output, args.incremental)
    elif args.export == 'csv':
        return exporter.export_to_csv_stream(args.output, args.incremental)
    return False

def run_interactive_mode(exporter: PocketExporter):
    """Run interactive menu mode"""
    print("\nPocket Exporter - Interactive Mode")
    print("=" * 40)

    while True:
        print("\nOptions:")
        print("1. Full export to JSON (streaming)")
        print("2. Full export to CSV (streaming)")
        print("3. Incremental export to JSON") 
        print("4. Incremental export to CSV")
        print("5. Exit")
 
        try:
            choice = input("\nSelect option (1-5): ").strip()

            if choice == '1':
                success = exporter.export_to_json_stream()
                print(
                    "Export completed successfully!" if success else 
                    "Export failed. Check logs for details."
                )
            elif choice == '2':
                success = exporter.export_to_csv_stream()
                print(
                    "CSV export completed successfully!" if success else
                    "CSV export failed. Check logs for details."
                )
            elif choice == '3':
                success = exporter.export_to_json_stream(incremental=True)
                print(
                    "Incremental export completed!" if success else
                    "Incremental export failed. Check logs for details."
                )
            elif choice == '4':
                success = exporter.export_to_csv_stream(incremental=True)
                print(
                    "Incremental CSV export completed!" if success else
                    "Incremental CSV export failed. Check logs for details."
                )
            elif choice == '5':
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please try again.")
    
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except EOFError:
            print("\nExiting...")
            break

def main():
    """Main application entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level, args.log_file)

    if not args.quiet:
        print("Production Pocket Exporter v2.1 - OAuth Fixed")
        print("=" * 50)

    # Load configuration
    config = ExportConfig.from_file(args.config)

    # Get consumer key
    consumer_key = args.consumer_key or os.environ.get('POCKET_CONSUMER_KEY')

    if not consumer_key:
        if args.interactive:
            consumer_key = input("Enter your Pocket consumer key: ").strip()
        else:
            print("Error: Consumer key required. Use --consumer-key or set POCKET_CONSUMER_KEY environment variable.")
            print("Get a consumer key at: https://getpocket.com/developer/apps/new")
            sys.exit(1)

    if not consumer_key:
        print("Consumer key required. Get one at: https://getpocket.com/developer/apps/new")
        sys.exit(1)

    try:
        exporter = PocketExporter(consumer_key, config)
 
        # Authenticate
        if not exporter.authenticate():
            print("Authentication failed. Try running with --log-level DEBUG for more details.")
            sys.exit(1)
    
        # Run in appropriate mode
        if args.interactive:
            run_interactive_mode(exporter)
        else:
            success = run_cli_export(args, exporter)
            if success:
                if not args.quiet:
                    print("Export completed successfully!")
            else:
                print("Export failed. Check logs for details.")
                sys.exit(1)
             
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if not args.quiet:
            print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
