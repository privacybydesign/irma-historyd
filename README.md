irma-historyd
=============

`irma-historyd` is a simple webserver that listens for the HTTP callbacks
send by `irma_api_server` and `irma_keyshare_server` and registers the
events that triggered them in a database.

Installation
------------

Run

    go get github.com/privacybydesign/irma-historyd

Create a `config.yaml` file, eg.

    db: mysql   # or postgres, sqlite3
    dsn: user:password@/databasename
    bindaddr: ":8080"
    # allowedauthorizationtokens:
    #    - somesecrettoken
