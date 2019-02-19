package main

import (
	"net/http"

	"github.com/mozilla-services/foxsec-pipeline-contrib/foxsec-slack-bot"
)

func main() {
	http.HandleFunc("/", foxsecslackbot.FoxsecSlackBot)
	http.ListenAndServe(":8888", nil)
}
