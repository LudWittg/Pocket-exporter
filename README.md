# Pocket Exporter

A tool for exporting your Pocket reading list.

## Features

- **Secure Authentication**: OAuth2 with encrypted token storage using system keyring
- **Multiple Export Formats**: JSON and CSV output options
- **Streaming Processing**: Handle large datasets without memory issues
- **Incremental Exports**: Export only new/modified items since last run
- **Resumable Operations**: Checkpoint system for interrupted exports
- **Rate Limiting**: Intelligent rate limiting with exponential backoff
- **Error Handling**: Comprehensive retry logic and graceful error recovery
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Prerequisites

- Python 3.8 or higher
- A Pocket consumer key (see setup instructions below)
- **Required**: `requests` library
- **Recommended**: `cryptography` and `keyring` libraries for secure token storage

## Installation

### Quick Install

```bash
# Clone or download the repository
git clone https://github.com/LudWittg/Pocket-exporter.git
cd pocket-exporter

# Create and activate virtual environment (recommended)
uv venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows

# Install with uv (recommended) - creates console script
uv pip install -e .

# Or with pip - creates console script
pip install -e .

# After installation, use the console script:
pocket-exporter --help

# Alternative: Run directly without installation
python pocket_exporter.py --help
```

### Manual Installation

If you prefer to install dependencies manually:

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Linux/Mac
# or
venv\Scripts\activate      # Windows

# Required dependency
pip install requests

# Recommended for secure token storage
pip install cryptography keyring

# Then run directly
python pocket_exporter.py --export json --consumer-key YOUR_KEY
```

**Note**: Without `cryptography` and `keyring`, tokens will be stored in encrypted files instead of the system keyring.

## Getting a Pocket Consumer Key

Before using the exporter, you need to register an application with Pocket:

1. Go to [Pocket Developer Portal](https://getpocket.com/developer/apps/new)
2. Click "Create New App"
3. Fill out the form:
   - **Application Name**: Choose any name (e.g., "My Pocket Exporter")
   - **Application Description**: Brief description of your use
   - **Permissions**: Select "Retrieve"
   - **Platforms**: Select "Desktop (other)"
4. Click "Create Application"
5. Copy your **Consumer Key** from the app details page

## Usage

### Command Line Interface

#### Basic Export

```bash
# Export all items to JSON (with console script)
pocket-exporter --consumer-key YOUR_KEY --export json

# Or run directly
python pocket_exporter.py --consumer-key YOUR_KEY --export json

# Export all items to CSV
pocket-exporter --consumer-key YOUR_KEY --export csv

# Specify output filename
pocket-exporter --consumer-key YOUR_KEY --export json --output my_backup.json
```

#### Incremental Export

```bash
# Export only new/modified items since last export
pocket-exporter --consumer-key YOUR_KEY --export json --incremental

# Incremental CSV export
pocket-exporter --consumer-key YOUR_KEY --export csv --incremental
```

#### Environment Variable

Set your consumer key as an environment variable to avoid typing it each time:

```bash
# Set environment variable
export POCKET_CONSUMER_KEY="your-consumer-key-here"

# Now you can run without --consumer-key
pocket-exporter --export json

# Interactive mode will prompt for key if not set
pocket-exporter --interactive
```

#### Interactive Mode

```bash
# Launch interactive menu
pocket-exporter --consumer-key YOUR_KEY --interactive
```

### Authentication

The first time you run the exporter:

1. The tool will open your web browser automatically
2. You'll be redirected to Pocket's authorization page
3. Click "Authorize" to grant access
4. The browser will show a success message
5. Your access token will be securely stored for future use

**Note**: The OAuth process uses a local HTTP server on `localhost:8080` for the callback. This is standard practice and secure.

### Command Line Options

```
Required:
  --export {json,csv}     Export format
  --consumer-key KEY      Pocket API consumer key (or set POCKET_CONSUMER_KEY env var)

Optional:
  --output FILE, -o FILE  Output filename (auto-generated if not specified)
  --incremental          Export only items modified since last export
  --interactive, -i      Run in interactive menu mode (prompts for missing options)
  --quiet, -q            Suppress progress output (errors still shown)
  --log-level LEVEL      Logging level (DEBUG, INFO, WARNING, ERROR)
  --log-file FILE        Log file path (default: pocket_exporter.log)
  --config FILE          Configuration file path (default: pocket_config.json)
  --help                 Show help message
```

### Configuration File

Create a `pocket_config.json` file to customize behavior:

```json
{
  "batch_size": 500,
  "max_retries": 5,
  "base_delay": 1.0,
  "max_delay": 60.0,
  "timeout": 30,
  "checkpoint_interval": 100,
  "daily_limit": 9500,
  "hourly_limit": 300
}
```

## Output Formats

### JSON Export

The JSON export includes complete item data with metadata:

```json
{
  "export_date": "2025-01-15T10:30:00",
  "export_type": "full",
  "items": [
    {
      "item_id": "123456789",
      "resolved_id": "123456789",
      "given_url": "https://example.com/article",
      "resolved_url": "https://example.com/article",
      "given_title": "Article Title",
      "resolved_title": "Article Title",
      "excerpt": "Article excerpt...",
      "is_article": true,
      "word_count": 1250,
      "time_added": "2025-01-10T09:15:00",
      "time_read": "2025-01-11T14:30:00",
      "status": "archived",
      "favorite": false,
      "tags": ["technology", "programming"],
      "authors": ["John Doe"],
      "images": ["https://example.com/image.jpg"],
      "videos": []
    }
  ],
  "total_items": 1
}
```

### CSV Export

The CSV export flattens complex data for spreadsheet compatibility:

| item_id | given_url | given_title | status | favorite | tags | time_added | word_count |
|---------|-----------|-------------|---------|----------|------|------------|------------|
| 123456789 | https://example.com | Article Title | archived | false | technology, programming | 2025-01-10T09:15:00 | 1250 |

## Incremental Exports

Incremental exports only fetch items that have been added or modified since your last export:

- Saves time and API calls for large libraries
- Perfect for regular backups
- Automatically tracks last export timestamp
- Works with both JSON and CSV formats

```bash
# First run: exports everything
pocket-exporter --export json

# Subsequent runs: only exports new/modified items
pocket-exporter --export json --incremental
```

## Troubleshooting

### Authentication Issues

If authentication fails:

```bash
# Run with debug logging to see detailed OAuth flow
pocket-exporter --export json --log-level DEBUG
# Or: python pocket_exporter.py --export json --log-level DEBUG
```

Common issues:
- **Browser doesn't open**: Copy the authorization URL from the logs and open manually
- **"Connection refused" on localhost:8080**: Make sure port 8080 isn't blocked by firewall or used by another application
- **OAuth timeout**: The tool waits 5 minutes for authorization - complete the process within this time
- **Token storage fails**: Install `keyring` and `cryptography` packages for secure storage, otherwise tokens are stored in encrypted files

### Rate Limiting

The tool automatically handles Pocket's API rate limits:
- **Daily limit**: 9,500 requests per day
- **Hourly limit**: 300 requests per hour

If you hit limits, the tool will wait automatically and resume.

### Large Exports

For very large libraries (10,000+ items):
- Use JSON format for better performance
- The tool uses streaming to handle any size library
- Exports are resumable if interrupted
- Consider incremental exports for regular backups

### Common Error Messages

**"Consumer key required"**
- Set your consumer key with `--consumer-key YOUR_KEY` or `POCKET_CONSUMER_KEY` environment variable
- Use `--interactive` mode to be prompted for the key

**"Authentication failed"**
- Check your consumer key is correct
- Ensure you completed the browser authorization step
- Try running with `--log-level DEBUG` for more details

**"Rate limited"**
- The tool will automatically wait and retry
- Consider reducing `batch_size` in config file

## File Locations

The tool creates these files in your home directory:

- **Encrypted access tokens**: `~/.pocket_token_*` (or system keyring if available)
- **Encryption keys**: `~/.pocket_key_*` (or system keyring if available)  
- **Export metadata**: `~/.pocket_export_meta_*` (tracks last export time for incremental exports)
- **Checkpoints**: `~/.pocket_checkpoints/checkpoint_*.json` (for resumable exports)
- **Log files**: `pocket_exporter.log` (in current directory, or specify with `--log-file`)

**Note**: Files are named with a hash of your consumer key to avoid conflicts when using multiple Pocket apps.

## Security

- Access tokens are encrypted using industry-standard encryption (Fernet)
- Tokens stored in system keyring when available
- OAuth uses secure HTTPS connections
- Local HTTP server only used for OAuth callback (standard practice)
- No sensitive data logged (except in DEBUG mode)

## API Limits

Pocket API limits (per consumer key):
- 9,500 requests per day
- 300 requests per hour
- The tool automatically respects these limits

## Examples

### Daily Backup Script

```bash
#!/bin/bash
export POCKET_CONSUMER_KEY="your-key-here"

# Daily incremental backup
python pocket_exporter.py --export json --incremental --quiet

# Archive with date
cp pocket_export_incremental_*.json "backups/pocket_$(date +%Y%m%d).json"
```

### Full Backup

```bash
# Complete library export with custom filename
pocket-exporter --export json --output "pocket_full_backup_$(date +%Y%m%d).json"
```

### CSV for Analysis

```bash
# Export to CSV for analysis in Excel/Google Sheets
pocket-exporter --export csv --output pocket_data.csv
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check this README and inline help (`--help`)
- **Debugging**: Use `--log-level DEBUG` for detailed information

## Changelog

### v0.1.0 (Current)
- Initial release
- JSON and CSV export support  
- Secure token storage
- Incremental exports
- Streaming processing
- Rate limiting and retry logic
