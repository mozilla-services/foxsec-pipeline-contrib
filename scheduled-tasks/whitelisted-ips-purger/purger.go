package purger

import (
	"context"
	"net/http"
	"os"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	PROJECT_ID string
	DB         *common.DBClient
)

func init() {
	mozlogrus.Enable("purger")
	PROJECT_ID = os.Getenv("GCP_PROJECT")

	var err error
	DB, err = common.NewDBClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Fatalf("Error creating db client: %s", err)
	}
}

func Purger(w http.ResponseWriter, r *http.Request) {
	err := DB.RemoveExpiredWhitelistedIps(r.Context())
	if err != nil {
		log.Errorf("Error removing expired whitelisted ips: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
