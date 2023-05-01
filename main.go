package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type User struct {
	Id         string     `json:"id"`
	Email      string     `json:"email"`
	Password   string     `json:"password"`
	Wallet     string     `json:"wallet"`
	PrivateKey string     `json:"privateKey"`
	Friends    []Friend   `json:"friends"`
	Timelines  []Timeline `json:"timelines"`
}

type Friend struct {
	Id string `json:"id"`
}

type Timeline struct {
	Id           string        `json:"id"`
	Transactions []Transaction `json:"transaction"`
}

type Transaction struct {
	Id        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	data      string    `json:"data"`
	hash      string    `json:"hash"`
}

var db *badger.DB
var mutex sync.Mutex

var client *ethclient.Client

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	wss := os.Getenv("NETWORK_WSS")

	client, err = ethclient.Dial(wss)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize BadgerDB
	dbOpt := badger.DefaultOptions("./data")
	db, err = badger.Open(dbOpt)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	router := gin.Default()
	router.POST("api/v1/user", CreateUser)
	router.GET("api/v1/user/:id", GetUser)
	router.POST("api/v1/user/:id/friend", AddFriend)
	router.POST("api/v1/user/:id/timeline", AddTimeline)
	router.POST("api/v1/user/:id/timeline/:timelineId/transaction", AddTransaction)

	go monitorTransactions()

	router.Run(fmt.Sprintf(":%s", os.Getenv("PORT")))

}

func CreateUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.Id = user.Email
	user.Password = HashPassword(user.Password)
	user.Wallet, user.PrivateKey = CreateWallet()
	user.Wallet = "0x0000008735754EDa8dB6B50aEb93463045fc5c55" // TEST

	err := db.Update(func(txn *badger.Txn) error {
		if _, err := txn.Get([]byte(user.Id)); err == nil {
			return err
		}
		jsonUser, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(user.Id), jsonUser)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, user)
}

func GetUser(c *gin.Context) {
	id := c.Param("id")
	var user User
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(id))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, user)
}

func AddFriend(c *gin.Context) {
	id := c.Param("id")
	var friend Friend
	if err := c.ShouldBindJSON(&friend); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := db.Update(func(txn *badger.Txn) error {
		var user User
		item, err := txn.Get([]byte(id))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		if err != nil {
			return err
		}
		user.Friends = append(user.Friends, friend)
		jsonUser, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(id), jsonUser)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, friend)
}

func AddTimeline(c *gin.Context) {
	id := c.Param("id")
	var timeline Timeline
	if err := c.ShouldBindJSON(&timeline); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := db.Update(func(txn *badger.Txn) error {
		var user User
		item, err := txn.Get([]byte(id))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		if err != nil {
			return err
		}
		user.Timelines = append(user.Timelines, timeline)
		jsonUser, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(id), jsonUser)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, timeline)
}

func AddTransaction(c *gin.Context) {
	id := c.Param("id")
	timelineId := c.Param("timelineId")
	var transaction Transaction
	if err := c.ShouldBindJSON(&transaction); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := db.Update(func(txn *badger.Txn) error {
		var user User
		item, err := txn.Get([]byte(id))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		if err != nil {
			return err
		}
		for i, timeline := range user.Timelines {
			if timeline.Id == timelineId {
				user.Timelines[i].Transactions = append(user.Timelines[i].Transactions, transaction)
				break
			}
		}
		jsonUser, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(id), jsonUser)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, transaction)
}

func HashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func CreateWallet() (string, string) {
	mutex.Lock()
	defer mutex.Unlock()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey := hex.EncodeToString(key.D.Bytes())
	publicKey := hex.EncodeToString(elliptic.Marshal(key.Curve, key.X, key.Y))
	return publicKey, privateKey
}

func Sign(privateKey string, message string) string {
	key, _ := hex.DecodeString(privateKey)
	hasher := sha256.New()
	hasher.Write([]byte(message))
	hash := hasher.Sum(nil)
	r, s, _ := ecdsa.Sign(rand.Reader, &ecdsa.PrivateKey{D: new(big.Int).SetBytes(key)}, hash)
	return hex.EncodeToString(r.Bytes()) + hex.EncodeToString(s.Bytes())
}

func Verify(publicKey string, message string, signature string) bool {
	key, _ := hex.DecodeString(publicKey)
	r, _ := hex.DecodeString(signature[:len(signature)/2])
	s, _ := hex.DecodeString(signature[len(signature)/2:])
	hasher := sha256.New()
	hasher.Write([]byte(message))
	hash := hasher.Sum(nil)
	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash, new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
}

func monitorTransactions() {
	var usdcContractAddress = os.Getenv("USDC_CONTRACT_ADDRESS")
	usdcAddress := common.HexToAddress(usdcContractAddress)
	query := ethereum.FilterQuery{
		Addresses: []common.Address{usdcAddress},
	}

	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			processLog(vLog)
		}
	}
}

func processLog(vLog types.Log) {
	if len(vLog.Topics) > 0 {
		// Check if the event is a Transfer event
		transferEventSignature := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
		if vLog.Topics[0] == transferEventSignature {
			from := common.HexToAddress(vLog.Topics[1].Hex())
			to := common.HexToAddress(vLog.Topics[2].Hex())
			amount := new(big.Int).SetBytes(vLog.Data)

			log.Printf("Transfer event: from=%s to=%s amount=%s\n", from.String(), to.String(), amount.String())

			// Iterate through users in the database
			err := db.View(func(txn *badger.Txn) error {
				iter := txn.NewIterator(badger.DefaultIteratorOptions)
				defer iter.Close()
				for iter.Rewind(); iter.Valid(); iter.Next() {
					item := iter.Item()
					err := item.Value(func(val []byte) error {
						var user User
						err := json.Unmarshal(val, &user)
						if err != nil {
							return err
						}

						// Check if the 'from' or 'to' address is in the user's wallet
						if from.String() == user.Wallet || to.String() == user.Wallet {
							log.Printf("User %s involved in the transaction: %s\n", user.Id, amount.String())

							// Add the transaction to the user's timelines
							transaction := Transaction{
								Id:        "test-id", // TODO: use hash of transaction data
								Timestamp: time.Now(),
							}

							if from.String() == user.Wallet {
								transaction.data = fmt.Sprintf("Sent %s USDC to %s", amount.String(), to.String())
							} else {
								transaction.data = fmt.Sprintf("Received %s USDC from %s", amount.String(), from.String())
							}

							for _, timeline := range user.Timelines {
								err := addTransactionToTimeline(user.Id, timeline.Id, transaction)
								if err != nil {
									log.Printf("Error adding transaction to timeline: %s\n", err.Error())
								}
							}
						}

						return nil
					})
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				log.Printf("Error processing log: %s\n", err.Error())
			}
		}
	}
}

func addTransactionToTimeline(userId string, timelineId string, transaction Transaction) error {
	return db.Update(func(txn *badger.Txn) error {
		var user User
		item, err := txn.Get([]byte(userId))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		if err != nil {
			return err
		}
		for i, timeline := range user.Timelines {
			if timeline.Id == timelineId {
				user.Timelines[i].Transactions = append(user.Timelines[i].Transactions, transaction)
				break
			}
		}
		jsonUser, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(userId), jsonUser)
		return err
	})
}
