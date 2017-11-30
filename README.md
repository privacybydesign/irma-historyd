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

    db: mysql  # other options: postgres, sqlite3
    dsn: user:password@/databasename
    bindaddr: ":8080"

    # # require a authorization token on requests
    # allowedauthorizationtokens:
    #   - O63KsRLHEl3I6eaEioIwaY

    # # Path to GeoLite2/GeoIP2 database.
    # # Download from http://dev.maxmind.com/geoip/geoip2/geolite2/
    # geodb: GeoLite2-City.mmdb

And run the daemon:

    $GOPATH/bin/irma-historyd
