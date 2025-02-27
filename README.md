# OpenAPI JWT Token Generator

This tool generates JWT tokens for API authentication with specific claims and configurations.

## Requirements

- Python 3.6+
- Required Python packages:
  - PyJWT
  - cryptography

## Installation

1. Clone this repository:
   ```
   git clone <your-repository-url>
   cd openapi-token-gen
   ```

2. Install required packages:
   ```
   pip install pyjwt cryptography
   ```

3. Create your configuration file:
   ```
   cp config.template.json config.json
   ```

4. Edit the `config.json` file with your specific values:
   - `subject`: The JWT subject claim
   - `api_key`: Your API key
   - `storefrontStoreCode`: Your storefront code
   - `additional_claims`: Any additional claims you want to include
   - `private_key`: Your RSA private key in PEM format

## Usage

### Graphical User Interface (Windows App)

This project includes a graphical user interface for easier token generation:

1. Run the UI application:
   ```
   python token_generator_app.py
   ```
   
2. Or build a standalone Windows executable:
   ```
   build.bat
   ```
   Then run the generated executable `dist\JWT_Token_Generator.exe`

The GUI provides:
- Form fields for all configuration values
- Options to load and save configuration files
- Simple token generation with a click
- Copy token functionality for easy use
- Display of token details and usage instructions

### Command Line Usage

Generate a JWT token using the default configuration:

```
python generate_jwt_token.py
```

### Command Line Options

- `--config`: Specify the path to your config file (default: `config.json`)
- `--iat-offset`: Set the "Issued At" time offset in minutes (positive for future, negative for past)
- `--output`: Specify the output file for token results (default: `jwt_token_result.json`)

Examples:

```
# Use a custom configuration file
python generate_jwt_token.py --config my_config.json

# Generate token with IAT 5 minutes in the future
python generate_jwt_token.py --iat-offset 5

# Specify a custom output file
python generate_jwt_token.py --output my_token.json
```

## Output

The script generates two outputs:

1. Console output with the token and key information
2. A JSON file (default: `jwt_token_result.json`) containing:
   - The JWT token
   - The storefront store code
   - IAT (Issued At) time
   - Token generation time

## Notes

- Tokens are typically valid for 30 minutes after generation
- Use the token in your API requests with the `Authorization` header or `x-auth-token` parameter
- Your configuration file contains sensitive information and should not be committed to version control