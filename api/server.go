package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// Ensure that we implement the server interface
var _ ServerInterface = (*Server)(nil)

type Server struct{
	logger *zap.SugaredLogger
}

func NewServer(logger *zap.SugaredLogger) *Server {
	return &Server{
		logger: logger,
	}
}

func (s *Server) RatsdChares(w http.ResponseWriter, r *http.Request, param RatsdCharesParams) {
	var requestData ChaResRequest

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		s.logger.Error("fail to retrieve nonce from request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logger.Info("request nonce: ", requestData.Nonce)
	s.logger.Info("request media type: ", *(param.Accept))
	w.Header().Set("Content-Type", "application/eat+jwt; eat_profile=\"tag:github.com,2024:veraison/ratsd\"")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello, rastd!"))
}
