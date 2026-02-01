# Secure App - Twitter Clone with Security Best Practices

A Twitter-like social media application built from the ground up with security as the primary focus. This project demonstrates comprehensive security engineering practices including authentication, authorization, input validation, rate limiting, and secure session management.

> **Project Status**: Active development. Core security features are implemented and functional. The codebase demonstrates production-ready security patterns and architecture, though some features are still being refined.

## 🛡️ Security Features Implemented

### Authentication & Authorization
- **Multi-Factor Authentication (MFA)**: Time-based one-time password system via email
- **JWT-based Sessions**: Stateless authentication with configurable expiration
- **Secure Password Storage**: bcrypt hashing with automatic salting (cost factor: 14)
- **Password Reset Flow**: Secure token-based password recovery with expiration
- **Token Expiration**: 5-minute MFA tokens, 15-minute password reset tokens, 24-hour JWT sessions

### Input Validation & Sanitization
- **Comprehensive Input Sanitization**: Removes control characters and potentially harmful content
- **Length Validation**: Prevents buffer overflow attacks with strict input limits
- **Content Security**: HTML entity escaping on the frontend to prevent XSS
- **SQL Injection Prevention**: Parameterized queries throughout the application
- **Email Validation**: Proper email format verification

### Rate Limiting
- **IP-based Rate Limiting**: Different limits for different endpoints
  - Login/Registration: 5 requests per minute per IP
  - Tweet Creation: 5 requests per minute per IP
- **Distributed Rate Limiter Support**: Per-IP tracking with automatic cleanup
- **Brute Force Protection**: Prevents automated attack attempts

### Network Security
- **HTTPS Enforcement**: Automatic redirect from HTTP to HTTPS in production
- **CORS Configuration**: Controlled cross-origin resource sharing
- **Secure Headers**: Production-ready security headers
- **TLS/STARTTLS Support**: Encrypted email communication

### Database Security
- **Parameterized Queries**: Complete protection against SQL injection
- **Password Never Stored in Plain Text**: All passwords hashed before storage
- **Secure Token Storage**: Reset and MFA tokens properly managed
- **Cascading Deletes**: Proper referential integrity
- **Indexed Queries**: Performance optimization without security compromise

### Session Management
- **Secure Token Generation**: Cryptographically secure random token generation
- **Token Invalidation**: MFA tokens cleared after successful use
- **Expiration Enforcement**: Automatic token expiration with UTC timestamps
- **No Token Reuse**: Single-use tokens for sensitive operations

## 🏗️ Architecture

### Backend (Go)
- **Framework**: Gorilla Mux for routing
- **Database**: PostgreSQL with connection pooling
- **JWT**: golang-jwt for token management
- **Password Hashing**: bcrypt (golang.org/x/crypto)
- **Rate Limiting**: golang.org/x/time/rate
- **Email**: Native Go SMTP with STARTTLS support

### Frontend (Vanilla JavaScript)
- **No Framework Dependencies**: Lightweight and auditable
- **XSS Prevention**: HTML escaping for all user content
- **Secure Storage**: LocalStorage for tokens (production would use httpOnly cookies)
- **CSRF Awareness**: Token-based authentication prevents CSRF

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

## 🚀 Setup & Installation

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

## 🔐 Security Considerations for Production

### Current Implementation
This is a demonstration project. For production deployment, consider:

1. **Environment Variables**: All secrets loaded from environment, never hardcoded
2. **JWT Secret**: Uses environment variable (falls back to default for dev only)
3. **HTTPS**: Enforcement middleware included
4. **Rate Limiting**: Implemented but set to development-friendly limits

### Production Recommendations
- [ ] Use httpOnly, Secure, SameSite cookies instead of localStorage
- [ ] Implement CSRF token protection
- [ ] Add Content Security Policy headers
- [ ] Use TOTP (Time-based OTP) instead of email-based MFA
- [ ] Implement session revocation
- [ ] Add security headers (HSTS, X-Frame-Options, etc.)
- [ ] Set up database connection encryption
- [ ] Implement proper logging and monitoring
- [ ] Add API request signing
- [ ] Use a secrets management service (Vault, AWS Secrets Manager)
- [ ] Implement account lockout after failed attempts
- [ ] Add honeypot fields for bot detection
- [ ] Set up automated security scanning (SAST/DAST)

## 🧪 Testing Security Features

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

## 📊 API Endpoints

### Public Endpoints
- `POST /api/register` - User registration with automatic MFA
- `POST /api/login` - Login with optional MFA verification
- `POST /api/password-reset/request` - Request password reset
- `POST /api/password-reset/confirm` - Confirm password reset with code

### Protected Endpoints (Require JWT)
- `GET /api/tweets` - Fetch recent tweets
- `POST /api/tweets` - Create a new tweet

## 🎯 Skills Demonstrated

This project showcases expertise in:

- **Secure Authentication Patterns**: MFA, JWT, password hashing, session management
- **Input Validation**: Sanitization, length checks, SQL injection prevention
- **Rate Limiting**: IP-based throttling, distributed rate limiting architecture
- **Cryptography**: Secure random generation, bcrypt, token management
- **API Security**: Authorization headers, token validation, endpoint protection
- **Database Security**: Parameterized queries, proper indexing, referential integrity
- **Email Security**: STARTTLS, secure SMTP communication
- **Frontend Security**: XSS prevention, secure token storage, CORS handling
- **Production Readiness**: Environment configuration, HTTPS enforcement, security headers
- **Go Best Practices**: Error handling, middleware patterns, structured logging

## 📝 Code Quality

- **No Hardcoded Secrets**: All sensitive data from environment
- **Comprehensive Error Handling**: Secure error messages that don't leak information
- **Security-First Design**: Every feature built with security considerations
- **Clean Code**: Well-structured, commented, and maintainable
- **Logging**: Security events logged for audit trails
- **Type Safety**: Strong typing throughout the application

## 🤝 Contributing

This is a portfolio/demonstration project, but feedback on security improvements is always welcome!

## 🔄 Development Notes

This project is under active development with ongoing improvements to:
- Rate limiting configurations based on testing
- MFA token expiration timings (recently updated from 30s to 5min based on UX testing)
- Email delivery reliability
- Error handling and logging

The iterative development process demonstrates real-world engineering: testing, refining, and improving based on practical use cases.

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

**Security Engineer Portfolio Project**

This application was built to demonstrate security engineering skills including authentication systems, input validation, rate limiting, and secure coding practices. It represents a foundation that could be extended with additional security features for production use.

---

**⚠️ Disclaimer**: This is a demonstration project built for portfolio purposes. While it implements many security best practices, additional hardening would be required for production deployment.
