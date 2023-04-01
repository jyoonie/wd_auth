package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"wd_auth/store"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) Ping(c *gin.Context) {
	l := s.l.Named("Ping")

	if err := s.db.Ping(); err != nil {
		l.Error("could not ping", zap.Error(err)) //what level you use depending on what went wrong?
		c.Status(http.StatusInternalServerError)
		return
	} //디비에서부터 에러 뜨면 걍 여기서 리턴해라

	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func (s *Service) Homepage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func (s *Service) Login(c *gin.Context) {
	l := s.l.Named("Login")

	var loginRequest Login

	if err := json.NewDecoder(c.Request.Body).Decode(&loginRequest); err != nil { //decode 한다음에 그 내용이 valid한지 비교해야지 바보야.. 저 위에 var loginRequest create 한거는 새로 생긴거자나.. 으이구
		l.Info("error logging in", zap.Error(err))
		c.Status(http.StatusBadRequest)
		return
	}

	if !isValidLoginRequest(loginRequest) {
		l.Info("error logging in")
		c.Status(http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByEmail(context.Background(), loginRequest.EmailAddress)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			l.Info("error logging in", zap.Error(err))
			c.Status(http.StatusNotFound)
			return
		}
		l.Error("error logging in", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(loginRequest.Password)); err != nil {
		l.Info("error logging in", zap.Error(err))
		c.Status(http.StatusBadRequest)
		return
	}

	// Create the claims
	claims := jwt.RegisteredClaims{
		// A usual scenario is to set the expiration time relative to the current time
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "whatDoIEatToday",
		ID:        user.UserUUID.String(),
		Audience:  []string{"whatDoIEatToday"},
	}

	token := jwt.NewWithClaims(s.mySigningMethod, claims)
	signedToken, err := token.SignedString(s.mySigningKey)
	if err != nil {
		l.Error("error signing the token")
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, Token{Token: signedToken})
}

func (s *Service) ValidateToken(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if len(strings.Split(token, " ")) < 2 {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	} //return 했으므로 else 할 필요없음. return에 안걸리면 어차피 else에 해당하는 부분은 continue 되기 때문에.

	realToken := strings.Split(token, " ")[1]

	t, err := jwt.Parse(realToken, //getting rid of "bearer " from the original token
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.mySigningKey, nil //Parse method is going to use this function to reencrypt the body, so the first time you create the jwt, you know the first part is alg, second claim, third encrypted.
		},
		jwt.WithValidMethods([]string{s.mySigningMethod.Alg()}),
	)
	if err != nil || !t.Valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Status(http.StatusOK)
}