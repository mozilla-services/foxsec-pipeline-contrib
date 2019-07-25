module github.com/mozilla-services/foxsec-pipeline-contrib/auth0pull

go 1.12

require (
	cloud.google.com/go v0.36.0
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/mozlogrus v1.0.1-0.20171031175137-a4ca0c1ee1cb
	gopkg.in/auth0.v1 v1.2.4
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../
