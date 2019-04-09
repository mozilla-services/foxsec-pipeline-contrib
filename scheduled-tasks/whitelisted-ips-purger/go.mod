module github.com/mozilla-services/foxsec-pipeline-contrib/scheduled-tasks/whitelisted-ips-purger

require (
	cloud.google.com/go v0.36.0 // indirect
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/sirupsen/logrus v1.3.0
	go.mozilla.org/mozlog v0.0.0-20170222151521-4bb13139d403 // indirect
	go.mozilla.org/mozlogrus v1.0.0
	google.golang.org/genproto v0.0.0-20190219182410-082222b4a5c5 // indirect
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../../
