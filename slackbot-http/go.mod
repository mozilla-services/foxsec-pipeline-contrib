module github.com/mozilla-services/foxsec-pipeline-contrib/slackbot-http

require (
	cloud.google.com/go v0.36.0
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/lusis/go-slackbot v0.0.0-20180109053408-401027ccfef5 // indirect
	github.com/lusis/slack-test v0.0.0-20190426140909-c40012f20018 // indirect
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/nlopes/slack v0.6.0
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/mozlog v0.0.0-20170222151521-4bb13139d403 // indirect
	go.mozilla.org/mozlogrus v2.0.0+incompatible
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../

go 1.13
