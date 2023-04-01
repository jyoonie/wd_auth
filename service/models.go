package service

import (
	"github.com/google/uuid"
)

//authentication handler에서 email이랑 password만 따로 받아서 json으로 주고받는 login 모델을 만들어야겠찌?
//밑에 User struct에서 굳이 password 필드를 user한테 받자고 남겨두는 것보단.. 왜냐면 response에서는 이 password 필드를 항상 empty로 둘거니께..

type User struct {
	UserUUID uuid.UUID `json:"user_uuid,omitempty"`
	//HashedPassword string    `json:"hashed_password,omitempty"`
	Active       bool   `json:"active,omitempty"`
	FirstName    string `json:"first_name,omitempty"`
	LastName     string `json:"last_name,omitempty"`
	EmailAddress string `json:"email_address,omitempty"`
	//CreatedAt    time.Time `json:"created_at,omitempty"`
	//UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type Login struct {
	EmailAddress string `json:"email_address,omitempty"`
	Password     string `json:"password,omitempty"`
}

type Token struct { //토큰은 서버에 저장하는게 아니라 db 모델은 업쯤.
	Token string `json:"token,omitempty"`
}
