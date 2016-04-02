package auth

import (
	"github.com/micro/go-micro/client"
	"golang.org/x/net/context"
)

type Options struct {
	ID      string
	Secret  string
	BaseURL string
	Client  client.Client
	// Used for alternative options
	Context context.Context
}

func Client(c client.Client) Option {
	return func(o *Options) {
		o.Client = c
	}
}

func ID(id string) Option {
	return func(o *Options) {
		o.ID = id
	}
}

func Secret(s string) Option {
	return func(o *Options) {
		o.Secret = s
	}
}

func BaseURL(s string) Option {
	return func(o *Options) {
		o.BaseURL = s
	}
}
