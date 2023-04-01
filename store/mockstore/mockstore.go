package mockstore

import (
	"context"
	"wd_auth/store"

	"github.com/google/uuid"
)

var _ store.Store = (*Mockstore)(nil)

type Mockstore struct {
	PingOverride func() error

	GetUserOverride        func(ctx context.Context, id uuid.UUID) (*store.User, error)
	GetUserByEmailOverride func(ctx context.Context, email string) (*store.User, error)
	CreateUserOverride     func(ctx context.Context, u store.User) (*store.User, error)
	UpdateUserOverride     func(ctx context.Context, u store.User) (*store.User, error)
}
