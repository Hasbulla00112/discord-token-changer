# Discord Token Changer

A high-performance, multi-threaded utility for changing Discord tokens with advanced security features.

## Features

- **Multi-Threading Support**: Process multiple tokens simultaneously for maximum efficiency
- **Proxy Integration**: Automatically rotates through proxies to prevent rate limiting and IP bans
- **Resilient Error Handling**: Smart retry mechanism with fallback options when encountering errors
- **User-Friendly Interface**: Color-coded console output for easy monitoring of operations
- **Advanced Security**: Uses TLS fingerprinting prevention and proper encryption for secure token changing
- **Real-Time Statistics**: Live tracking of success rates, failures, and progress
- **Token Format Support**: Handles both raw tokens and email:pass:token formats

## Technical Details

- Implements WebSocket connections for Discord's remote authentication protocol
- Uses RSA encryption for secure key exchange
- Features proper TLS client configuration to avoid detection
- Automatically manages token validation and logout procedures
- Saves results in real-time to prevent data loss

## Usage

1. Place your tokens in `input/input.txt` (one per line)
2. Add proxies to `input/proxies.txt` if needed
3. Configure thread count and proxy usage in `config.json`
4. Run the script and monitor progress in the console
5. Find changed tokens in the timestamped output directory

## Configuration

Customize operation through the `config.json` file:
- `threads`: Number of concurrent workers (default: 10)
- `proxies`: Enable/disable proxy usage (default: true)

## Requirements

- Python 3.7+
- Required libraries: tls-client, websocket-client, cryptography, colorama

## Disclaimer

This tool is provided for educational purposes only. Use responsibly and in accordance with Discord's Terms of Service.
