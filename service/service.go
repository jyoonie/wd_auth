package service

import (
	"wd_auth/store"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

type Service struct {
	r               *gin.Engine
	db              store.Store
	l               *zap.Logger
	mySigningKey    []byte
	mySigningMethod jwt.SigningMethod
}

func New(s store.Store, l *zap.Logger) *Service {
	newService := &Service{r: gin.Default(), db: s, l: l}

	newService.mySigningKey = []byte("jyoonieisthebestandsheisprettyandsheissmart") //signing key는 HS512의 경우 80자 권장..ㄷㄷ 길수록 좋음
	newService.mySigningMethod = jwt.SigningMethodHS512

	newService.registerRoutes()

	return newService
}

func (s *Service) Run() {
	l := s.l.Named("Run") //logger specifically created for this function

	if err := s.r.Run(); err != nil {
		l.Fatal("service failed to start", zap.Error(err))
	}
}
