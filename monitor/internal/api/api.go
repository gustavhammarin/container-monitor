package api

import (
	"container-monitor/internal/logger"
	"encoding/json"
	"net/http"
)

type API struct{
	log *logger.Logger
	State *PollState
}

func New(l *logger.Logger) *API {
	return &API{log: l, State: Init()}
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /logs/network", a.networkLogs)
	mux.HandleFunc("GET /logs/trivy", a.trivyLogs)
	mux.HandleFunc("GET /logs/falco", a.falcoLogs)
	mux.HandleFunc("GET /status", a.getStatus)
	return http.ListenAndServe(addr, cors(mux))
}

func (a *API) getStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(a.State)
}

func (a *API) networkLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := a.log.GetNetworkLogs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}

func (a *API) trivyLogs(w http.ResponseWriter, r *http.Request){
	logs, err := a.log.GetTrivyLogs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return 
	}
	json.NewEncoder(w).Encode(logs)
}

func (a *API) falcoLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := a.log.GetFalcoLogs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}