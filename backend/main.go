package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key-change-in-production")

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
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "All fields required", http.StatusBadRequest)
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

	// Print MFA token to terminal
	fmt.Printf("\n🔐 MFA TOKEN for %s: %s\n\n", req.Email, mfaToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Registration successful. Check terminal for MFA code.",
		"user_id":   userID,
		"username":  req.Username,
		"mfa_token": mfaToken,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid request"})
		return
	}

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
		fmt.Printf("\n🔐 MFA TOKEN for %s: %s (reusing from registration)\n\n", req.Email, mfaToken)
	} else {
		// Generate new MFA token and store it (in UTC)
		mfaToken = generateMFAToken(user.MFASecret)
		mfaExpires := time.Now().UTC().Add(5 * time.Minute)
		
		// Update the database with new token
		db.Exec(
			"UPDATE users SET last_mfa_token = $1, last_mfa_token_expires = $2 WHERE email = $3",
			mfaToken, mfaExpires, req.Email,
		)
		
		fmt.Printf("\n🔐 MFA TOKEN for %s: %s\n\n", req.Email, mfaToken)
	}

	// MFA code not provided, request it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "MFA required. Check terminal for code.",
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

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := enableCORS(router)
	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}