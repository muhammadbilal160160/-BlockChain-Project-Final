package main

import (
	"crypto-wallet-backend/config"
	"crypto-wallet-backend/handlers"
	"log"

	"cloud.google.com/go/firestore"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load config
	cfg := config.LoadConfig()

	// Initialize Firestore
	client, err := firestore.NewClient(nil, cfg.ProjectID)
	if err != nil {
		log.Fatalf("Failed to initialize Firestore: %v", err)
	}
	defer client.Close()

	// Initialize router
	r := gin.Default()

	// Handlers
	r.POST("/transaction", handlers.CreateTransaction(client, cfg))
	r.GET("/transactions/:walletId", handlers.GetTransactionHistory(client))
	r.GET("/pending-transactions", handlers.GetPendingTransactions(client))
	r.GET("/blockchain", handlers.GetBlockchain(client))
	r.GET("/blocks/:index", handlers.GetBlock(client))
	r.POST("/mine", handlers.MineBlock(client, cfg))

	// Start server
	r.Run(":" + cfg.Port)
}
