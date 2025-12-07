package handlers

import (
	"context"
	"crypto-wallet-backend/crypto"
	"crypto-wallet-backend/models"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Signup handles user registration
func Signup(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.SignupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := context.Background()

		// Check if user already exists
		iter := client.Collection("users").Where("email", "==", req.Email).Documents(ctx)
		doc, err := iter.Next()
		if doc != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
			return
		}

		// Generate key pair and wallet
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate keys"})
			return
		}

		// Hash password
		passwordHash, err := crypto.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Encrypt private key with user's password
		encryptedPrivateKey, err := crypto.EncryptPrivateKey(keyPair.PrivateKey, req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt private key"})
			return
		}

		// Generate OTP
		otp := fmt.Sprintf("%06d", rand.Intn(1000000))
		otpExpiry := time.Now().Add(10 * time.Minute).Unix()

		// Create user
		userID := uuid.New().String()
		user := models.User{
			UserID:              userID,
			Email:               req.Email,
			FullName:            req.FullName,
			CNIC:                req.CNIC,
			WalletID:            keyPair.WalletID,
			PublicKey:           keyPair.PublicKey,
			EncryptedPrivateKey: encryptedPrivateKey,
			Beneficiaries:       []string{},
			CreatedAt:           time.Now().Unix(),
			OTPCode:             otp,
			OTPExpiry:           otpExpiry,
			IsVerified:          false,
			PasswordHash:        passwordHash,
		}

		// Save user to Firestore
		_, err = client.Collection("users").Doc(userID).Set(ctx, user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		// Create wallet
		wallet := models.Wallet{
			WalletID:  keyPair.WalletID,
			UserID:    userID,
			Balance:   0,
			PublicKey: keyPair.PublicKey,
			CreatedAt: time.Now().Unix(),
		}

		_, err = client.Collection("wallets").Doc(keyPair.WalletID).Set(ctx, wallet)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create wallet"})
			return
		}

		// TODO: Send OTP via email (implement email service)
		fmt.Printf("OTP for %s: %s\n", req.Email, otp)

		c.JSON(http.StatusCreated, gin.H{
			"message": "User created. Please verify OTP sent to your email.",
			"userId":  userID,
			"email":   req.Email,
		})
	}
}

// VerifyOTP handles OTP verification
func VerifyOTP(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.OTPVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := context.Background()

		// Find user by email
		iter := client.Collection("users").Where("email", "==", req.Email).Documents(ctx)
		doc, err := iter.Next()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		var user models.User
		doc.DataTo(&user)

		// Check OTP
		if user.OTPCode != req.OTP {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
			return
		}

		// Check OTP expiry
		if time.Now().Unix() > user.OTPExpiry {
			c.JSON(http.StatusBadRequest, gin.H{"error": "OTP expired"})
			return
		}

		// Update user as verified
		_, err = client.Collection("users").Doc(user.UserID).Update(ctx, []firestore.Update{
			{Path: "isVerified", Value: true},
			{Path: "otpCode", Value: ""},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
	}
}

// Login handles user login
func Login(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := context.Background()

		// Find user by email
		iter := client.Collection("users").Where("email", "==", req.Email).Documents(ctx)
		doc, err := iter.Next()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		var user models.User
		doc.DataTo(&user)

		// Check if user is verified
		if !user.IsVerified {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Please verify your email first"})
			return
		}

		// Check password
		if !crypto.CheckPasswordHash(req.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Generate JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userId":   user.UserID,
			"walletId": user.WalletID,
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte("your-secret-key")) // Use env variable
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":    tokenString,
			"userId":   user.UserID,
			"walletId": user.WalletID,
			"fullName": user.FullName,
			"email":    user.Email,
		})
	}
}

// GoogleAuth handles Google OAuth (placeholder)
func GoogleAuth(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement Google OAuth
		c.JSON(http.StatusNotImplemented, gin.H{"message": "Google OAuth not implemented yet"})
	}
}
