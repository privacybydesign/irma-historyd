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
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/oschwald/geoip2-golang"
	"gopkg.in/yaml.v2"

	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Globals
var (
	conf  Conf
	db    *gorm.DB
	geoDb *geoip2.Reader
)

// Configuration
type Conf struct {
	DB                         string // type of database, eg. "mysql"
	DSN                        string // DSN, eg.  "dbuser:password@/database"
	AllowedAuthorizationTokens []string
	BindAddr                   string // address to bind to, eg. ":8080"
	GeoDb                      string // path to GeoLite2/GeoIP2 db
}

// Data sent along with a "/submit" POST request.
type SubmitRequest struct {
	Issuances       []IssueEvent
	Registrations   []RegistrationEvent
	Unregistrations []UnregistrationEvent
	Logins          []LoginEvent
	PinsBlocked     []PinBlockedEvent
	EmailsVerified  []EmailVerifiedEvent
}

type Event interface {
	Store() error
}

// For each event, we have a struct (eg. IssueEvent) with the data sent in the
// POST request and a struct (eg. IssueEventRecord) with the fields stored
// in the database.

// Records an issued attribute
type IssueEvent struct {
	When      time.Time
	Attribute string
	IP        string
}
type IssueEventRecord struct {
	ID        uint      `gorm:"primary_key"`
	When      time.Time `gorm:"index"`
	Attribute string
	Country   string
	City      string
}

func (IssueEventRecord) TableName() string { return "issue_events" }

func (e *IssueEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := IssueEventRecord{
		When:      e.When,
		Attribute: e.Attribute,
		Country:   country,
		City:      city,
	}
	return db.Create(&rec).Error
}

// Records a registration on the keyshareserver
type RegistrationEvent struct {
	When   time.Time
	Double bool
	IP     string
}
type RegistrationEventRecord struct {
	ID      uint      `gorm:"primary_key"`
	When    time.Time `gorm:"index"`
	Double  bool
	Country string
	City    string
}

func (RegistrationEventRecord) TableName() string { return "registration_events" }

func (e *RegistrationEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := RegistrationEventRecord{
		When:    e.When,
		Double:  e.Double,
		Country: country,
		City:    city,
	}
	return db.Create(&rec).Error
}

// Records the verification of an e-mail address on the keyshareserver
type EmailVerifiedEvent struct {
	When time.Time
	IP   string
}
type EmailVerifiedEventRecord struct {
	ID      uint      `gorm:"primary_key"`
	When    time.Time `gorm:"index"`
	Country string
	City    string
}

func (EmailVerifiedEventRecord) TableName() string { return "email_verified_events" }

func (e *EmailVerifiedEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := EmailVerifiedEventRecord{
		When:    e.When,
		Country: country,
		City:    city,
	}
	return db.Create(&rec).Error
}

// Records an unregistration on the keyshareserver
type UnregistrationEvent struct {
	When time.Time
	IP   string
}
type UnregistrationEventRecord struct {
	ID      uint      `gorm:"primary_key"`
	When    time.Time `gorm:"index"`
	Country string
	City    string
}

func (UnregistrationEventRecord) TableName() string { return "unregistration_events" }

func (e *UnregistrationEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := UnregistrationEventRecord{
		When:    e.When,
		Country: country,
		City:    city,
	}
	return db.Create(&rec).Error
}

// Records a login attempt
type LoginEvent struct {
	When    time.Time
	Success bool
	WithOTP bool
	IP      string
}
type LoginEventRecord struct {
	ID      uint      `gorm:"primary_key"`
	When    time.Time `gorm:"index"`
	Success bool
	WithOTP bool
	Country string
	City    string
}

func (LoginEventRecord) TableName() string { return "login_events" }

func (e *LoginEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := LoginEventRecord{
		When:    e.When,
		Country: country,
		Success: e.Success,
		WithOTP: e.WithOTP,
		City:    city,
	}
	return db.Create(&rec).Error
}

// Records a pin being blocked
type PinBlockedEvent struct {
	When time.Time
	IP   string
}
type PinBlockedEventRecord struct {
	ID      uint      `gorm:"primary_key"`
	When    time.Time `gorm:"index"`
	Country string
	City    string
}

func (e *PinBlockedEvent) Store() error {
	country, city := geoLookup(e.IP)
	rec := PinBlockedEventRecord{
		When:    e.When,
		Country: country,
		City:    city,
	}
	return db.Create(&rec).Error
}
func (PinBlockedEventRecord) TableName() string { return "pin_blocked_events" }

func (r *SubmitRequest) List() []Event {
	ret := []Event{}
	for _, event := range r.Issuances {
		ret = append(ret, &event)
	}
	for _, event := range r.Registrations {
		ret = append(ret, &event)
	}
	for _, event := range r.Unregistrations {
		ret = append(ret, &event)
	}
	for _, event := range r.Logins {
		ret = append(ret, &event)
	}
	for _, event := range r.PinsBlocked {
		ret = append(ret, &event)
	}
	for _, event := range r.EmailsVerified {
		ret = append(ret, &event)
	}
	return ret
}

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

	// open geo database, if available
	if conf.GeoDb != "" {
		log.Println("Opening geo database ...")
		geoDb, err = geoip2.Open(conf.GeoDb)
		if err != nil {
			log.Fatalf(" failed to open %s: %s", conf.GeoDb, err)
		}
		defer geoDb.Close()
		log.Println(" ok")
	} else {
		log.Println("Note: 'geodb' not set")
	}

	// connect to database
	log.Println("Connecting to database ...")
	db, err = gorm.Open(conf.DB, conf.DSN)

	if err != nil {
		log.Fatalf(" %s: could not connect to %s: %s", conf.DB, conf.DSN, err)
	}
	defer db.Close()
	log.Println(" ok")

	log.Println("Auto-migration (if necessary) ...")
	db.AutoMigrate(
		IssueEventRecord{},
		RegistrationEventRecord{},
		EmailVerifiedEventRecord{},
		UnregistrationEventRecord{},
		LoginEventRecord{},
		PinBlockedEventRecord{})
	log.Println(" ok")

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

// Look up IP address
func geoLookup(ip string) (countryCode string, city string) {
	pIp := net.ParseIP(ip)
	if pIp == nil {
		return
	}
	record, err := geoDb.City(pIp)
	if err != nil {
		log.Printf("geoLookup(%s): %s", ip, err)
		return
	}
	return record.Country.IsoCode, record.City.Names["en"]
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

	for _, event := range events.List() {
		if err := event.Store(); err != nil {
			log.Printf("Error while inserting event: %s", err)
			continue
		}
		nRegistered++
	}

	fmt.Fprintf(w, "ok, registered %d", nRegistered)
	log.Printf("Registered %d", nRegistered) // TODO remove
}
