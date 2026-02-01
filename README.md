# Secure Twitter Clone

A full-stack social media application demonstrating security engineering principles. Built with Go and PostgreSQL, this project implements multi-layered security controls including MFA, rate limiting, input validation, and secure session management.

**Status**: Core security features implemented and tested. Currently refining authentication flow and rate limiting configurations.

## Security Features

### Authentication & Authorization
- Multi-factor authentication via email-based OTP
- JWT-based stateless sessions with 24-hour expiration
- bcrypt password hashing (cost factor: 14) with constant-time comparison
- Secure password reset with time-limited tokens
- Token expiration: 30-second MFA codes, 15-minute password reset tokens
- Generic error messages prevent account enumeration

### Input Validation & Sanitization
- Server-side input sanitization removes control characters
- Length validation prevents buffer overflow attacks (5000 char limit)
- HTML entity escaping on frontend prevents XSS
- Parameterized SQL queries prevent injection attacks
- Email format validation

### Rate Limiting
- IP-based rate limiting with configurable thresholds per endpoint
- Login/Registration: 5 requests per minute per IP
- Tweet Creation: 60 requests per minute per IP  
- Per-IP tracking prevents distributed brute force attacks
- Automatic cleanup of rate limiter state

### Network Security
- HTTPS enforcement via middleware (production)
- CORS configuration for controlled cross-origin access
- TLS/STARTTLS support for email transmission
- Proxy-aware IP extraction (X-Forwarded-For, X-Real-IP)

### Database Security
- Parameterized queries prevent SQL injection
- Passwords stored as bcrypt hashes only
- Indexed queries on frequently accessed columns
- Foreign key constraints with cascading deletes
- UTC timestamps prevent timezone manipulation

### Session Management
- Cryptographically secure token generation (crypto/rand)
- Single-use MFA tokens with automatic invalidation
- UTC-based expiration enforcement
- No token reuse for sensitive operations
- Session fixation protection through token regeneration

## Architecture

### Backend (Go)
- Gorilla Mux for HTTP routing
- PostgreSQL for data persistence
- golang-jwt/jwt for token management
- bcrypt for password hashing
- golang.org/x/time/rate for rate limiting
- Native SMTP with STARTTLS

### Frontend (Vanilla JavaScript)
- No framework dependencies for auditability
- HTML escaping prevents XSS
- LocalStorage for JWT tokens (trades CSRF protection for XSS vulnerability - httpOnly cookies recommended for production)
- Content Security Policy would mitigate XSS risk in production

### Database Schema
```sql
users
├── id (SERIAL PRIMARY KEY)
├── username (VARCHAR, UNIQUE)
├── email (VARCHAR, UNIQUE)
├── password_hash (VARCHAR)
├── mfa_secret (VARCHAR)
├── last_mfa_token (VARCHAR)
├── last_mfa_token_expires (TIMESTAMP)
├── reset_token (VARCHAR)
├── reset_token_expires (TIMESTAMP)
└── created_at (TIMESTAMP)

tweets
├── id (SERIAL PRIMARY KEY)
├── user_id (INTEGER, FOREIGN KEY)
├── content (TEXT)
└── created_at (TIMESTAMP, INDEXED)
```

## Setup & Installation

### Prerequisites
- Go 1.19+
- PostgreSQL 12+
- SMTP server (optional, for email functionality)

### Environment Variables
Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL=postgres://user:password@localhost/twitterclone?sslmode=disable

# JWT Secret (CHANGE THIS IN PRODUCTION!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Email Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
SMTP_FROM=your-email@gmail.com

# Server
PORT=8080
```

### Database Setup
```bash
# Create database
createdb twitterclone

# Tables will be created automatically on first run
```

### Running the Application
```bash
# Install dependencies
go mod download

# Run the server
cd backend
go run main.go
```

The application will be available at `http://localhost:8080`

## Production Security Considerations

### Current Implementation
Environment variables for secrets, JWT configuration, HTTPS middleware, and rate limiting are implemented. Some design choices prioritize simplicity for demonstration purposes.

### Additional Hardening for Production
- httpOnly, Secure, SameSite cookies instead of localStorage (eliminates XSS token theft)
- Content Security Policy headers to mitigate XSS attacks
- CSRF token protection for cookie-based sessions
- TOTP-based MFA instead of email codes (email is unencrypted and interceptable)
- Session revocation mechanism
- Additional security headers (HSTS, X-Frame-Options, X-Content-Type-Options)
- Database connection encryption (TLS)
- Comprehensive audit logging with tamper protection
- API request signing for critical operations
- Secrets management service integration (HashiCorp Vault, AWS Secrets Manager)
- Account lockout after failed attempts with exponential backoff
- Automated security scanning integration (SAST/DAST)
- Web Application Firewall (WAF) integration

## Testing Security Features

### Manual Testing Scenarios

**1. MFA Flow**
```bash
# Register a new user
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"securepass123"}'

# Check email/console for MFA code
# Login with MFA code
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"securepass123","mfa_code":"123456"}'
```

**2. Rate Limiting**
```bash
# Test rate limiting by making rapid requests
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}' &
done
```

**3. Input Validation**
```bash
# Test SQL injection protection
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com'\'' OR 1=1--","password":"test"}'

# Test XSS protection
curl -X POST http://localhost:8080/api/tweets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content":"<script>alert(\"XSS\")</script>"}'
```

**4. Password Reset Flow**
```bash
# Request password reset
curl -X POST http://localhost:8080/api/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# Confirm with reset code
curl -X POST http://localhost:8080/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","reset_code":"CODE_FROM_EMAIL","new_password":"newpassword123"}'
```

## API Endpoints

### Public Endpoints
- `POST /api/register` - User registration with automatic MFA
- `POST /api/login` - Login with optional MFA verification
- `POST /api/password-reset/request` - Request password reset
- `POST /api/password-reset/confirm` - Confirm password reset with code

### Protected Endpoints (Require JWT)
- `GET /api/tweets` - Fetch recent tweets
- `POST /api/tweets` - Create a new tweet

## Technical Implementation

**Security Engineering:**
- Multi-factor authentication with email-based OTP
- JWT session management with proper expiration
- Password hashing with bcrypt (cost factor 14)
- Rate limiting with per-IP, per-endpoint controls
- Input sanitization and validation across all endpoints
- Parameterized SQL queries for injection prevention

**System Design:**
- Middleware architecture for cross-cutting concerns
- Cryptographically secure token generation
- UTC timestamp handling for timezone safety
- Environment-based configuration management
- RESTful API design
- Defense-in-depth security model

**Code Quality:**
- No hardcoded secrets
- Comprehensive error handling without information leakage
- Security event logging
- Clean, maintainable code structure

## Development Notes

Active development focuses on:
- Authentication flow refinement
- Rate limiting optimization based on testing  
- Email delivery reliability and fallback handling
- Error message consistency for security

This iterative approach demonstrates practical engineering: implement, test, refine based on real-world usage.

## License

MIT License

---

**Portfolio Project** - Demonstrates security engineering capabilities including authentication systems, input validation, rate limiting, and secure coding practices. Built to showcase practical security implementation skills.
