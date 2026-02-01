# Twitter Clone - Go Backend + Vanilla JS Frontend

A simple Twitter-like application with secure authentication, MFA, and encrypted password storage.

## Features

✅ User registration with salted password hashing (bcrypt)  
✅ MFA authentication (simulated tokens in terminal)  
✅ Password reset with secure tokens (15-minute expiration)  
✅ JWT-based session management  
✅ PostgreSQL database with encrypted storage  
✅ Tweet creation and timeline viewing  
✅ Clean vanilla JavaScript frontend  

## Tech Stack

**Backend:**
- Go 1.21+
- PostgreSQL
- gorilla/mux (routing)
- golang-jwt/jwt (authentication)
- bcrypt (password hashing)

**Frontend:**
- Vanilla JavaScript
- CSS3
- No frameworks

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 12 or higher

## Setup Instructions

### 1. Install PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

### 2. Create Database

```bash
sudo -u postgres psql
```

In PostgreSQL prompt:
```sql
CREATE DATABASE twitterclone;
CREATE USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE twitterclone TO postgres;
\q
```

### 3. Install Go Dependencies

```bash
cd backend
go mod download
```

### 4. Run the Application

```bash
# From the backend directory
go run main.go
```

The server will start on `http://localhost:8080`

## Usage

### Registration Flow

1. Open `http://localhost:8080` in your browser
2. Click "Register" tab
3. Fill in username, email, and password
4. Click "Register"
5. **Check your terminal** - you'll see an MFA code printed like:
   ```
   🔐 MFA TOKEN for user@example.com: 123456
   ```
6. Switch to "Login" tab

### Login Flow

1. Enter your email and password
2. Click "Login"
3. **Check your terminal** - a new MFA code will be printed
4. Enter the 6-digit MFA code in the form
5. Click "Login" again
6. You're now logged in!

### Password Reset Flow

1. Click "Forgot Password?" on the login screen
2. Enter your email address
3. Click "Send Reset Code"
4. **Check your terminal** - you'll see a reset code like:
   ```
   🔑 PASSWORD RESET CODE for user@example.com: a1b2c3d4e5f6...
   Expires at: 14:30:45
   ```
5. Enter the reset code and your new password
6. Click "Reset Password"
7. You can now login with your new password!

**Note:** Reset codes expire after 15 minutes for security.

### Using the Dashboard

- **Post tweets:** Type in the text area and click "Tweet" (max 280 characters)
- **View timeline:** See all tweets from all users in chronological order
- **Logout:** Click the "Logout" button in the header

## Security Features

### Password Security
- Passwords are hashed using **bcrypt** with cost factor 14
- Each password gets a unique salt automatically
- Passwords are never stored in plain text
- Password hashes are never exposed via API

### MFA (Multi-Factor Authentication)
- Each user gets a unique MFA secret on registration
- MFA tokens are simulated 6-digit codes (printed to terminal)
- In production, this would use TOTP (Google Authenticator, etc.)
- MFA required for every login

### JWT Authentication
- JWTs expire after 24 hours
- Tokens include user ID and username claims
- All protected routes require valid JWT
- Tokens are stored client-side in localStorage

### Database Security
- PostgreSQL with proper user permissions
- SQL injection prevention via prepared statements
- Cascade deletion for data integrity
- Indexed queries for performance

## API Endpoints

### Public Endpoints

**POST /api/register**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

**POST /api/login**
```json
{
  "email": "john@example.com",
  "password": "securepassword123",
  "mfa_code": "123456"
}
```

**POST /api/password-reset/request**
```json
{
  "email": "john@example.com"
}
```

**POST /api/password-reset/confirm**
```json
{
  "email": "john@example.com",
  "reset_code": "a1b2c3d4e5f6...",
  "new_password": "newSecurePassword456"
}
```

### Protected Endpoints (Require JWT)

**GET /api/tweets**
- Returns array of recent tweets
- Header: `Authorization: Bearer <token>`

**POST /api/tweets**
```json
{
  "content": "Hello Twitter!"
}
```
- Header: `Authorization: Bearer <token>`

## Database Schema

### users table
```sql
id                   SERIAL PRIMARY KEY
username             VARCHAR(50) UNIQUE NOT NULL
email                VARCHAR(100) UNIQUE NOT NULL
password_hash        VARCHAR(255) NOT NULL
mfa_secret           VARCHAR(32) NOT NULL
reset_token          VARCHAR(32)
reset_token_expires  TIMESTAMP
created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
```

### tweets table
```sql
id         SERIAL PRIMARY KEY
user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE
content    TEXT NOT NULL
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
```

## Production Considerations

For production deployment, you should:

1. **Change JWT Secret:** Replace `jwtSecret` with a strong random key from environment variable
2. **Use HTTPS:** Enable TLS/SSL for all connections
3. **Implement Real TOTP:** Replace simulated MFA with proper TOTP (e.g., using `pquerna/otp`)
4. **Add Rate Limiting:** Prevent brute force attacks
5. **Enable HTTPS-only Cookies:** For storing JWTs more securely
6. **Add Email Verification:** Verify email addresses before activation
7. **Implement Password Requirements:** Enforce strong password policies
8. **Add Logging & Monitoring:** Track security events
9. **Database Connection Pooling:** Use proper connection management
10. **Environment Variables:** Move all config to env vars

## Troubleshooting

**Database Connection Error:**
```
Check that PostgreSQL is running: sudo systemctl status postgresql
Verify credentials in main.go match your database setup
```

**MFA Code Not Appearing:**
```
Make sure you're looking at the terminal where `go run main.go` is running
MFA codes are printed to stdout
```

**CORS Errors:**
```
Ensure frontend is being served from http://localhost:8080
Check that CORS middleware is enabled
```

## License

MIT License - feel free to use for learning and projects!
