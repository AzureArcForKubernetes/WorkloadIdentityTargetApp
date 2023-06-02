package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func main() {
	fmt.Println("Hello World!")

	StartProxyServer()
}

func StartProxyServer() {
	fmt.Println("Starting proxy server...")
	http.HandleFunc("/", authenticateRequestBasedOnRules)
	err := http.ListenAndServe(":8082", nil)
	if err != nil {
		fmt.Printf("Failed to start server: %s", err)
		os.Exit(1)
	}
}

func authenticateRequestBasedOnRules(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Authenticating the request")

	// Get the Azure AD JWKS URL.
	jwksURL := "https://login.microsoftonline.com/common/discovery/v2.0/keys"

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		fmt.Printf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
		os.Exit(1)
	}

	// Get a JWT token to validate.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Handle missing token error
		fmt.Println("Missing authentication token")
		http.Error(w, "Missing authentication token", http.StatusUnauthorized)
		return
	}
	splitToken := strings.Split(authHeader, "Bearer ")
	jwtToken := splitToken[1]

	// Parse the JWT.
	token, err := jwt.Parse(jwtToken, jwks.Keyfunc)
	if err != nil {
		fmt.Printf("Failed to parse the JWT.\nError: %s", err.Error())
		os.Exit(1)
	}

	// Validate the JWT token.
	if !token.Valid {
		fmt.Println("The JWT token is invalid.")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	fmt.Println("The JWT token is valid.")
	fmt.Println("Authtorizing the request")

	// Access the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		// Handle invalid claims format error
		fmt.Println("Invalid claims format")
		http.Error(w, "Invalid claim format", http.StatusUnauthorized)
		return
	}

	// Extract specific claims
	appid, ok := claims["appid"].(string)
	if !ok {
		// Handle missing or invalid appid claim error
		fmt.Println("Invalid appid claim")
		http.Error(w, "Invalid appid claim", http.StatusUnauthorized)
		return
	}

	// Get appid from header
	appidHeader := r.Header.Get("Appid")
	if appidHeader == "" {
		// Handle missing token error
		fmt.Println("Missing appid")
		http.Error(w, "Missing appid", http.StatusUnauthorized)
		return
	}

	if appid != appidHeader {
		fmt.Println("Mismatch appid")
		http.Error(w, "Invalid appid", http.StatusUnauthorized)
		return
	}

	fmt.Println("The appid is valid.")
	fmt.Println("The request is authorized.")

	// Create a response
	response := struct {
		AppSecret string `json:"appSecret"`
	}{
		AppSecret: "Secret Value",
	}

	// Convert the response data to JSON
	responseJSON, err := json.Marshal(response)
	if err != nil {
		// Handle error if JSON marshaling fails
		http.Error(w, "Failed to create JSON response", http.StatusInternalServerError)
		return
	}

	// Set the content type to JSON in the response headers
	w.Header().Set("Content-Type", "application/json")

	// Set the HTTP status code
	w.WriteHeader(http.StatusOK)

	// Write the JSON response
	w.Write(responseJSON)

	fmt.Println("Sent response with secret back to client.")
}
