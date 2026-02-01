package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key-change-in-production")

// Rate limiters for different endpoints
var (
	// 5 requests per minute per IP for login/register
	loginLimiter = make(map[string]*rate.Limiter)
	// 10 requests per minute per IP for tweets
	tweetLimiter = make(map[string]*rate.Limiter)
)

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	MFASecret    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Tweet struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type TweetRequest struct {
	Content string `json:"content"`
}

type ResetPasswordRequest struct {
	Email string `json:"email"`
}

type ConfirmResetRequest struct {
	Email       string `json:"email"`
	ResetCode   string `json:"reset_code"`
	NewPassword string `json:"new_password"`
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func initDB() {
	var err error
	connStr := "user=postgres password=postgres dbname=twitterclone sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		mfa_secret VARCHAR(32) NOT NULL,
		last_mfa_token VARCHAR(6),
		last_mfa_token_expires TIMESTAMP,
		reset_token VARCHAR(32),
		reset_token_expires TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tweets (
		id SERIAL PRIMARY KEY,
		user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_tweets_created ON tweets(created_at DESC);
	`

	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Database initialized successfully")
}

func generateMFASecret() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateMFAToken(secret string) string {
	// Simulated MFA token - in production use TOTP
	bytes := make([]byte, 4)
	rand.Read(bytes)
	// Convert to number and ensure it's always 6 digits (000000-999999)
	num := int(bytes[0])<<24 | int(bytes[1])<<16 | int(bytes[2])<<8 | int(bytes[3])
	if num < 0 {
		num = -num
	}
	return fmt.Sprintf("%06d", num%1000000)
}

func generateResetToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password string) (string, error) {
	// bcrypt automatically salts the password
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func sendMFAEmail(email, mfaCode string) error {
	// Get email configuration from environment
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpFrom := os.Getenv("SMTP_FROM")

	// Debug logging
	log.Printf("DEBUG: SMTP_HOST=%s, SMTP_USER=%s, SMTP_PASSWORD_LENGTH=%d\n", smtpHost, smtpUser, len(smtpPassword))

	// If email config not set, fall back to printing to console
	if smtpHost == "" || smtpUser == "" || smtpPassword == "" {
		fmt.Printf("\n⚠️  Email not configured. MFA CODE for %s: %s\n\n", email, mfaCode)
		return nil
	}

	// Compose email
	subject := "Your MFA Code"
	body := fmt.Sprintf(`
Your MFA authentication code is: %s

This code will expire in 5 minutes.

Do not share this code with anyone.

If you did not request this code, please ignore this email.
`, mfaCode)

	// Create email message
	from := mail.Address{Name: "Twitter Clone", Address: smtpFrom}
	to := mail.Address{Address: email}

	// Headers
	headers := make(map[string]string)
	headers["From"] = from.String()
	headers["To"] = to.String()
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""

	// Build message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// Send email via SMTP
	addr := smtpHost + ":" + smtpPort
	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)

	// For Gmail and similar services that require STARTTLS on port 587
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("❌ Error connecting to SMTP server (%s): %v", addr, err)
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		log.Printf("❌ Error creating SMTP client: %v", err)
		return err
	}
	defer client.Close()

	// Upgrade connection to TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtpHost,
	}

	if err = client.StartTLS(tlsConfig); err != nil {
		log.Printf("❌ Error starting TLS: %v", err)
		return err
	}

	if err = client.Auth(auth); err != nil {
		log.Printf("❌ Error authenticating with SMTP: %v", err)
		return err
	}

	if err = client.Mail(from.Address); err != nil {
		log.Printf("❌ Error setting sender: %v", err)
		return err
	}

	if err = client.Rcpt(to.Address); err != nil {
		log.Printf("❌ Error setting recipient: %v", err)
		return err
	}

	wc, err := client.Data()
	if err != nil {
		log.Printf("❌ Error getting writer: %v", err)
		return err
	}
	defer wc.Close()

	if _, err = wc.Write([]byte(message)); err != nil {
		log.Printf("❌ Error writing message: %v", err)
		return err
	}

	client.Quit()
	log.Printf("✅ MFA code sent to %s\n", email)
	return nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID int, username string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// sanitizeInput removes potentially harmful characters and HTML
func sanitizeInput(input string) string {
	// Remove leading/trailing whitespace
	input = strings.TrimSpace(input)
	
	// Remove control characters
	input = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, input)
	
	// Limit length to prevent buffer overflow attacks
	if len(input) > 5000 {
		input = input[:5000]
	}
	
	return input
}

// getRateLimiter gets or creates a rate limiter for an IP
func getRateLimiter(ip string, limiterMap map[string]*rate.Limiter) *rate.Limiter {
	limiter, exists := limiterMap[ip]
	if !exists {
		// 5 requests per minute
		limiter = rate.NewLimiter(rate.Every(time.Second*12), 1)
		limiterMap[ip] = limiter
	}
	return limiter
}

// checkRateLimit checks if request is allowed
func checkRateLimit(ip string, limiterMap map[string]*rate.Limiter) bool {
	limiter := getRateLimiter(ip, limiterMap)
	return limiter.Allow()
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP if there are multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	
	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add claims to request context could go here
		next(w, r)
	}
}

// enforceHTTPS redirects HTTP to HTTPS in production
func enforceHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce in production (not localhost)
		if r.Header.Get("X-Forwarded-Proto") != "" && r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Check rate limit
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP, loginLimiter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"message": "Too many registration attempts. Please try again later."})
		log.Printf("⚠️ Rate limit exceeded for IP: %s\n", clientIP)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Sanitize inputs
	req.Username = sanitizeInput(req.Username)
	req.Email = sanitizeInput(req.Email)
	req.Password = sanitizeInput(req.Password)

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "All fields required", http.StatusBadRequest)
		return
	}

	// Validate username length (3-50 chars)
	if len(req.Username) < 3 || len(req.Username) > 50 {
		http.Error(w, "Username must be 3-50 characters", http.StatusBadRequest)
		return
	}

	// Validate password length (8+ chars)
	if len(req.Password) < 8 {
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Hash password
	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Generate MFA secret
	mfaSecret := generateMFASecret()

	// Generate MFA token and set 5-minute expiration (in UTC)
	mfaToken := generateMFAToken(mfaSecret)
	mfaExpires := time.Now().UTC().Add(5 * time.Minute)

	// Insert user with MFA token
	var userID int
	err = db.QueryRow(
		"INSERT INTO users (username, email, password_hash, mfa_secret, last_mfa_token, last_mfa_token_expires) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		req.Username, req.Email, passwordHash, mfaSecret, mfaToken, mfaExpires,
	).Scan(&userID)

	if err != nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Send MFA token via email
	if err := sendMFAEmail(req.Email, mfaToken); err != nil {
		log.Printf("Warning: Failed to send MFA email to %s: %v", req.Email, err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Registration successful. Check your email for MFA code.",
		"user_id":   userID,
		"username":  req.Username,
		"mfa_token": mfaToken,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Check rate limit
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP, loginLimiter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"message": "Too many login attempts. Please try again later."})
		log.Printf("⚠️ Rate limit exceeded for IP: %s\n", clientIP)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid request"})
		return
	}

	// Sanitize inputs
	req.Email = sanitizeInput(req.Email)
	req.MFACode = sanitizeInput(req.MFACode)

	fmt.Printf("DEBUG LOGIN: Email='%s', MFACode='%s'\n", req.Email, req.MFACode)

	// Get user
	var user User
	var lastMFAToken sql.NullString
	var lastMFAExpires sql.NullTime
	err := db.QueryRow(
		"SELECT id, username, email, password_hash, mfa_secret, last_mfa_token, last_mfa_token_expires FROM users WHERE email = $1",
		req.Email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.MFASecret, &lastMFAToken, &lastMFAExpires)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid credentials"})
		return
	}

	// Check password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid credentials"})
		return
	}

	// If MFA code provided, verify it against stored token
	if req.MFACode != "" {
		fmt.Printf("DEBUG: Token valid=%v, Expires valid=%v\n", lastMFAToken.Valid, lastMFAExpires.Valid)
		if lastMFAExpires.Valid {
			now := time.Now().UTC()
			expires := lastMFAExpires.Time.UTC()
			fmt.Printf("DEBUG: Now=%v, Expires=%v, IsExpired=%v\n", now, expires, now.After(expires))
		}
		
		// Check if there's a valid stored MFA token (use UTC for comparison)
		if !lastMFAToken.Valid || !lastMFAExpires.Valid || time.Now().UTC().After(lastMFAExpires.Time.UTC()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"message": "MFA token expired. Please request a new one."})
			return
		}

		fmt.Printf("DEBUG: Received MFA code: '%s', Expected: '%s'\n", req.MFACode, lastMFAToken.String)
		
		if req.MFACode != lastMFAToken.String {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"message": "Invalid MFA code"})
			return
		}

		// Generate JWT
		token, err := generateJWT(user.ID, user.Username)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": "Server error"})
			return
		}

		// Clear the MFA token after successful verification
		db.Exec("UPDATE users SET last_mfa_token = NULL, last_mfa_token_expires = NULL WHERE email = $1", req.Email)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":    token,
			"username": user.Username,
			"user_id":  user.ID,
		})
		return
	}

	// No MFA code provided - determine which token to send
	var mfaToken string
	
	// Check if there's a valid stored MFA token (within 5 minutes)
	if lastMFAToken.Valid && lastMFAExpires.Valid && time.Now().UTC().Before(lastMFAExpires.Time.UTC()) {
		// Use the existing token
		mfaToken = lastMFAToken.String
		log.Printf("Reusing existing MFA token for %s\n", req.Email)
	} else {
		// Generate new MFA token and store it (in UTC)
		mfaToken = generateMFAToken(user.MFASecret)
		mfaExpires := time.Now().UTC().Add(5 * time.Minute)
		
		// Update the database with new token
		db.Exec(
			"UPDATE users SET last_mfa_token = $1, last_mfa_token_expires = $2 WHERE email = $3",
			mfaToken, mfaExpires, req.Email,
		)
		
		// Send MFA code via email
		if err := sendMFAEmail(req.Email, mfaToken); err != nil {
			log.Printf("Warning: Failed to send MFA email to %s: %v", req.Email, err)
		}
	}

	// MFA code not provided, request it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "MFA required. Check your email for code.",
		"mfa_token": mfaToken,
	})
}

func requestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", req.Email).Scan(&userID)
	if err != nil {
		// Don't reveal if email exists - security best practice
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If that email exists, a reset code has been sent. Check terminal.",
		})
		return
	}

	// Generate reset token (valid for 15 minutes)
	resetToken := generateResetToken()
	expiresAt := time.Now().Add(15 * time.Minute)

	// Store reset token
	_, err = db.Exec(
		"UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3",
		resetToken, expiresAt, req.Email,
	)

	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Print reset code to terminal (simulates email)
	fmt.Printf("\n🔑 PASSWORD RESET CODE for %s: %s\n", req.Email, resetToken)
	fmt.Printf("   Expires at: %s\n\n", expiresAt.Format("15:04:05"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Reset code sent. Check terminal.",
		"reset_token": resetToken,
	})
}

func confirmPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfirmResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.ResetCode == "" || req.NewPassword == "" {
		http.Error(w, "All fields required", http.StatusBadRequest)
		return
	}

	// Verify reset token
	var resetToken string
	var expiresAt time.Time
	err := db.QueryRow(
		"SELECT reset_token, reset_token_expires FROM users WHERE email = $1",
		req.Email,
	).Scan(&resetToken, &expiresAt)

	if err != nil {
		http.Error(w, "Invalid reset request", http.StatusBadRequest)
		return
	}

	// Check token validity
	if resetToken != req.ResetCode {
		http.Error(w, "Invalid reset code", http.StatusUnauthorized)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, "Reset code expired", http.StatusUnauthorized)
		return
	}

	// Hash new password
	newPasswordHash, err := hashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Update password and clear reset token
	_, err = db.Exec(
		"UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE email = $2",
		newPasswordHash, req.Email,
	)

	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("\n✅ Password successfully reset for %s\n\n", req.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful. You can now login.",
	})
}

func getTweetsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT t.id, t.user_id, u.username, t.content, t.created_at
		FROM tweets t
		JOIN users u ON t.user_id = u.id
		ORDER BY t.created_at DESC
		LIMIT 50
	`)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	tweets := []Tweet{}
	for rows.Next() {
		var tweet Tweet
		err := rows.Scan(&tweet.ID, &tweet.UserID, &tweet.Username, &tweet.Content, &tweet.CreatedAt)
		if err != nil {
			continue
		}
		tweets = append(tweets, tweet)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tweets)
}

func createTweetHandler(w http.ResponseWriter, r *http.Request) {
	// Check rate limit
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP, tweetLimiter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"message": "Too many requests. Please slow down."})
		return
	}

	// Extract user from token
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	claims := &Claims{}
	jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	var req TweetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Sanitize tweet content
	req.Content = sanitizeInput(req.Content)

	if req.Content == "" || len(req.Content) > 280 {
		http.Error(w, "Tweet must be 1-280 characters", http.StatusBadRequest)
		return
	}

	var tweetID int
	err := db.QueryRow(
		"INSERT INTO tweets (user_id, content) VALUES ($1, $2) RETURNING id",
		claims.UserID, req.Content,
	).Scan(&tweetID)

	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Tweet created",
		"tweet_id": tweetID,
	})
}

func main() {
	// Load environment variables from .env file (check parent directory too)
	if err := godotenv.Load("../.env"); err != nil {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, using environment variables")
		} else {
			log.Println("✅ .env file loaded successfully from current directory")
		}
	} else {
		log.Println("✅ .env file loaded successfully from parent directory")
	}

	// Initialize database
	initDB()
	defer db.Close()

	// Setup router
	router := mux.NewRouter()

	// Public routes
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/password-reset/request", requestPasswordResetHandler).Methods("POST")
	router.HandleFunc("/api/password-reset/confirm", confirmPasswordResetHandler).Methods("POST")

	// Protected routes
	router.HandleFunc("/api/tweets", authMiddleware(getTweetsHandler)).Methods("GET")
	router.HandleFunc("/api/tweets", authMiddleware(createTweetHandler)).Methods("POST")

	// Serve frontend
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("../frontend")))

	// Add HTTPS enforcement middleware
	router.Use(enforceHTTPS)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Load JWT secret from environment
	jwtSecretEnv := os.Getenv("JWT_SECRET")
	if jwtSecretEnv != "" {
		jwtSecret = []byte(jwtSecretEnv)
		log.Println("✅ JWT secret loaded from environment")
	} else {
		log.Println("⚠️  Using default JWT secret. Set JWT_SECRET environment variable in production.")
	}

	handler := enableCORS(router)
	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}