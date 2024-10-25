# DRF-TOTP

TOTP (Time-based One-Time Password) authentication for Django REST Framework.

## Features

- Generate TOTP secrets for users
- Verify TOTP tokens
- Enable/disable TOTP authentication
- Check TOTP status
- Validate TOTP tokens

## Installation

```bash
pip install drf-totp
```

## Quick Start

1. Add "drf_totp" to your INSTALLED_APPS setting:

```python
INSTALLED_APPS = [
    ...
    'rest_framework',
    'drf_totp',
]
```

2. Include the TOTP URLconf in your project urls.py:

```python
path('auth/', include('drf_totp.urls')),
```

3. Run migrations:

```bash
python manage.py migrate
```

## Settings

Add these to your Django settings:

```python
# Optional: Set your TOTP issuer name (defaults to "drftotp")
TOTP_ISSUER_NAME = "Your App Name"
```

## API Endpoints

- `POST /auth/otp/generate/`: Generate new TOTP secret
- `POST /auth/otp/verify/`: Verify and enable TOTP
- `GET /auth/otp/status/`: Get TOTP status
- `POST /auth/otp/disable/`: Disable TOTP
- `POST /auth/otp/validate/`: Validate TOTP token

## Usage Example

```python
# Generate TOTP
response = requests.post('/auth/otp/generate/')
secret = response.json()['secret']
otpauth_url = response.json()['otpauth_url']

# Verify TOTP
response = requests.post('/auth/otp/verify/', {
    'token': '123456'  # 6-digit TOTP token
})

# Check Status
response = requests.get('/auth/otp/status/')

# Validate TOTP
response = requests.post('/auth/otp/validate/', {
    'token': '123456'  # 6-digit TOTP token
})
```

## License

MIT License - see LICENSE file for details.