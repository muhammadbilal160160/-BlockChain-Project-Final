package handlers

import (
	"context"
	"crypto-wallet-backend/utxo"
	"net/http"

	"cloud.google.com/go/firestore"
	"github.com/gin-gonic/gin"
)

// GetWallet retrieves wallet information
func GetWallet(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		walletID := c.Param("walletId")
		ctx := context.Background()

		doc, err := client.Collection("wallets").Doc(walletID).Get(ctx)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
			return
		}

		var wallet map[string]interface{}
		doc.DataTo(&wallet)

		c.JSON(http.StatusOK, wallet)
	}
}

// GetBalance retrieves wallet balance
func GetBalance(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		walletID := c.Param("walletId")
		ctx := context.Background()

		// Get UTXOs
		utxos, err := utxo.GetUTXOsForWallet(ctx, client, walletID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get balance"})
			return
		}

		// Calculate balance
		balance := utxo.CalculateBalance(utxos)

		c.JSON(http.StatusOK, gin.H{
			"walletId":  walletID,
			"balance":   balance,
			"utxoCount": len(utxos),
		})
	}
}

// GetUTXOs retrieves all UTXOs for a wallet
func GetUTXOs(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		walletID := c.Param("walletId")
		ctx := context.Background()

		utxos, err := utxo.GetUTXOsForWallet(ctx, client, walletID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get UTXOs"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"walletId": walletID,
			"utxos":    utxos,
			"count":    len(utxos),
		})
	}
}

// UpdateProfile updates user profile
func UpdateProfile(client *firestore.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("userId")

		var updates map[string]interface{}
		if err := c.ShouldBindJSON(&updates); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := context.Background()

		// Prevent updating sensitive fields
		delete(updates, "walletId")
		delete(updates, "publicKey")
		delete(updates, "encryptedPrivateKey")

		// Update user
		var firestoreUpdates []firestore.Update
		for key, value := range updates {
			firestoreUpdates = append(firestoreUpdates, firestore.Update{
				Path:  key,
				Value: value,
			})
		}

		_, err := client.Collection("users").Doc(userID).Update(ctx, firestoreUpdates)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
	}
}
