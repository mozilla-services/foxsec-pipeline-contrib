package purger

import (
	"net/http"
	"os"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var PROJECT_ID string

func init() {
	mozlogrus.Enable("purger")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
}

func Purger(w http.ResponseWriter, r *http.Request) {
	log.Debug("Creating db client")
	db, err := common.NewDBClient(r.Context(), PROJECT_ID)
	if err != nil {
		log.Errorf("Error creating db client: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer db.Close()
	log.Debug("db client created")

	err = db.RemoveExpiredWhitelistedIps(r.Context())
	if err != nil {
		log.Errorf("Error removing expired whitelisted ips: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
