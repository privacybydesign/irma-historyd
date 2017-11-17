// (c) 2017 - Bas Westerbaan <bas@westerbaan.name>
// You may redistribute this file under the conditions of the GPLv3.

// irma-historyd is a simple webserver that collects events from
// irma_api_server and irma_keyshare_server and stores it in a MySQL database.

package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"gopkg.in/yaml.v2"

	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Configuration
type Conf struct {
	DB                         string // type of database, eg. "mysql"
	DSN                        string // DSN, eg.  "dbuser:password@/database"
	AllowedAuthorizationTokens []string
	BindAddr                   string // address to bind to, eg. ":8080"
}

// Types for entries in the database tables
type IssueEvent struct {
	ID        uint `gorm:"primary_key"`
	When      time.Time
	Attribute string
}

// Type of JSON request sent to the server
type SubmitRequest struct {
	Issuances []IssueEvent
}

// Globals
var conf Conf
var db *gorm.DB

func main() {
	var confPath string

	// parse commandline
	flag.StringVar(&confPath, "config", "config.yaml",
		"Path to configuration file")
	flag.Parse()

	// parse configuration file
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Printf("Could not find config file: %s", confPath)
		fmt.Println("It should look like")
		fmt.Println("")
		fmt.Println("   db: mysql")
		fmt.Println("   dsn: dbuser:password@/database")
		fmt.Println("   bindaddr: ':8080'")
		os.Exit(1)
		return
	}

	buf, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatalf("Could not read config file %s: %s", confPath, err)
	}

	if err := yaml.Unmarshal(buf, &conf); err != nil {
		log.Fatalf("Could not parse config file: %s", err)
	}

	// connect to database
	log.Println("Connecting to database ...")
	db, err = gorm.Open(conf.DB, conf.DSN)

	if err != nil {
		log.Fatalf(" %s: could not connect to %s: %s", conf.DB, conf.DSN, err)
	}
	defer db.Close()

	log.Println("Auto-migration (if necessary) ...")
	db.AutoMigrate(&IssueEvent{})

	// set up HTTP server
	http.HandleFunc("/submit", submitHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi, this is irma-historyd.")
	})

	log.Printf("Listening on %s", conf.BindAddr)

	if len(conf.AllowedAuthorizationTokens) == 0 {
		log.Println("Warning: 'allowedauthorizationtokens' is empty!")
		log.Println("           --- I will accept data from anyone!")
	}

	log.Fatal(http.ListenAndServe(conf.BindAddr, nil))
}

// Check if the right authorization header is present
func checkAuthorization(w http.ResponseWriter, r *http.Request) bool {
	if len(conf.AllowedAuthorizationTokens) == 0 {
		return true
	}

	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(auth) != 2 || auth[0] != "Basic" {
		http.Error(w, "Bad or missing Authorization header", http.StatusBadRequest)
		return false
	}

	token := []byte(auth[1])
	for _, okToken := range conf.AllowedAuthorizationTokens {
		if subtle.ConstantTimeCompare(token, []byte(okToken)) == 1 {
			return true
		}
	}
	http.Error(w, "Access denied", http.StatusUnauthorized)
	return false
}

// Handle /submit HTTP requests used to submit events
func submitHandler(w http.ResponseWriter, r *http.Request) {
	var events SubmitRequest
	nRegistered := 0

	if !checkAuthorization(w, r) {
		return
	}

	err := json.Unmarshal([]byte(r.FormValue("events")), &events)
	if err != nil {
		http.Error(w, fmt.Sprintf(
			"Missing or malformed events form field: %s", err), 400)
		return
	}

	for _, issue := range events.Issuances {
		if err := db.Create(&issue).Error; err != nil {
			log.Printf("Error while inserting IssueEvent: %s", err)
			continue
		}
		nRegistered++
	}

	fmt.Fprintf(w, "ok, registered %d", nRegistered)
	log.Printf("Registered %d", nRegistered) // TODO remove
}
