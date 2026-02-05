# DRF-TOTP

TOTP (Time-based One-Time Password) authentication for Django REST Framework.

## 📊 Complete Workflow

### User Registration Flow

```
┌─────────────────┐
│    Sign Up      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  POST /generate/│─────▶│  Scan QR Code    │
└────────┬────────┘      └──────────────────┘
         │                        │
         │                        │
         ▼                        ▼
┌─────────────────┐      ┌──────────────────┐
│  Enter 6-digit  │      │ Open Authenticator│
│     Token       │      │   App (Google/   │
└────────┬────────┘      │    Authy/etc)    │
         │                └──────────────────┘
         ▼
┌─────────────────┐      ┌──────────────────────────┐
│  POST /verify/  │─────▶│ DB: is_confirmed = True  │
└────────┬────────┘      └──────────────────────────┘
         │
         ▼
   ✅ 2FA Enabled
```

### Login Flow (with 2FA)

```
┌─────────────────┐
│   Username &    │
│    Password     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  GET /status/   │─────▶│  TOTP Enabled?   │
└────────┬────────┘      └────────┬─────────┘
         │                        │
         │                   Yes  │
         ▼                        ▼
┌─────────────────┐      ┌──────────────────┐
│ POST /validate/ │◀─────│  Enter 6-digit   │
│  {token:123456} │      │   TOTP Code      │
└────────┬────────┘      └──────────────────┘
         │
         ▼
  ✅ Grant Access
```

### Disable 2FA Flow

```
┌─────────────────┐
│  User Settings  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│ POST /disable/  │◀─────│  Enter Current   │
│  {token:123456} │      │   TOTP Token     │
└────────┬────────┘      └──────────────────┘
         │
         ▼
┌─────────────────────────┐
│ DB: Delete TOTPDevice   │
└─────────────────────────┘
         │
         ▼
   ❌ 2FA Disabled
```

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

```javascript
import axios from "axios";

// Generate TOTP
export async function generateTotp() {
  try {
    const response = await axios.post("/auth/otp/generate/");
    const { secret, otpauth_url } = response.data;
    return { secret, otpauth_url };
  } catch (error) {
    console.error("Error generating TOTP:", error);
    throw error;
  }
}

// Verify TOTP
export async function verifyTotp(token) {
  try {
    const response = await axios.post("/auth/otp/verify/", { token });
    return response.data;
  } catch (error) {
    console.error("Error verifying TOTP:", error);
    throw error;
  }
}

// Check Status
export async function checkStatus() {
  try {
    const response = await axios.get("/auth/otp/status/");
    return response.data;
  } catch (error) {
    console.error("Error checking status:", error);
    throw error;
  }
}

// Validate TOTP
export async function validateTotp(token) {
  try {
    const response = await axios.post("/auth/otp/validate/", { token });
    return response.data;
  } catch (error) {
    console.error("Error validating TOTP:", error);
    throw error;
  }
}
```

## License

MIT License - see LICENSE file for details.
