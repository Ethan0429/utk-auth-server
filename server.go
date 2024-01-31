package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func init() {
	// setup dotenv
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}
}

// TokenData holds the token and guild ID
type TokenData struct {
	Token   string `json:"token"`
	GuildID string `json:"guild_id"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

// Generate a random token of 25 characters
func generateToken() (string, error) {
	bytes := make([]byte, 25)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:25], nil
}

// Handler for generating user token
func generateUserTokenHandler(w http.ResponseWriter, r *http.Request) {
	sharedSecret := os.Getenv("SHARED_SECRET")

	authHeader := r.Header.Get("X-Custom-Auth")
	if authHeader != sharedSecret {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userDiscordID := r.URL.Query().Get("user-discord-id")
	guildDiscordID := r.URL.Query().Get("guild-discord-id")

	if userDiscordID == "" || guildDiscordID == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	// check if id already exists
	{
		file, err := ioutil.ReadFile("tokens.json")
		if err != nil {
			if !os.IsNotExist(err) {
				http.Error(w, "tokens.json does not exist", http.StatusInternalServerError)
			}
		} else {
			var tokens map[string]TokenData
			err = json.Unmarshal(file, &tokens)
			if err != nil {
				http.Error(w, "Error parsing file", http.StatusInternalServerError)
			}

			if _, ok := tokens[userDiscordID]; ok {
				http.Error(w, "User already has a token", http.StatusConflict)
				return
			}
		}
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Read the existing tokens
	file, err := ioutil.ReadFile("tokens.json")
	if err != nil {
		if !os.IsNotExist(err) {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
		file = []byte("{}") // If the file does not exist, start with an empty JSON object
	}

	var tokens map[string]TokenData
	err = json.Unmarshal(file, &tokens)
	if err != nil {
		http.Error(w, "Error parsing file", http.StatusInternalServerError)
		return
	}

	// Add or update the token for the user
	tokens[userDiscordID] = TokenData{Token: token, GuildID: guildDiscordID}

	// Write the updated tokens back to the file
	updatedData, err := json.Marshal(tokens)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	err = ioutil.WriteFile("tokens.json", updatedData, 0644)
	if err != nil {
		http.Error(w, "Error writing to file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Token generated successfully")

	response := TokenResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler for verifying user token
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	userDiscordID := r.URL.Query().Get("user-discord-id")
	token := r.URL.Query().Get("token")

	if userDiscordID == "" || token == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	file, err := ioutil.ReadFile("tokens.json")
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	var tokens map[string]TokenData
	err = json.Unmarshal(file, &tokens)
	if err != nil {
		http.Error(w, "Error parsing file", http.StatusInternalServerError)
		return
	}

	if tokenData, ok := tokens[userDiscordID]; ok {
		if tokenData.Token == token {
			fmt.Fprintln(w, "Verification successful")
			// remove key from map
			delete(tokens, userDiscordID)
			// Write the updated tokens back to the file
			updatedData, err := json.Marshal(tokens)
			if err != nil {
				http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			}
			err = ioutil.WriteFile("tokens.json", updatedData, 0644)
			if err != nil {
				http.Error(w, "Error writing to file", http.StatusInternalServerError)
			}
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}

func main() {
	port := os.Getenv("PORT")
	http.HandleFunc("/generate-user-token", generateUserTokenHandler)
	http.HandleFunc("/verify", verifyHandler)

	fmt.Println("Server is running on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
