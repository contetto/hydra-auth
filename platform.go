package auth

import (
	"strings"
	"sync"
	"time"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/metadata"

	"golang.org/x/net/context"
)

type platform struct {
	opts Options

	sync.Mutex
	t *Token

	running bool
	exit    chan bool
}

type tokenKey struct{}

func newPlatform(opts ...Option) Auth {
	var options Options
	for _, o := range opts {
		o(&options)
	}
	if options.Client == nil {
		options.Client = client.DefaultClient
	}

	return &platform{
		opts: options,
	}
}

func (p *platform) run(ch <-chan bool) {
	// TODO: implement policy caching... hell implement policies
	return
}

func (p *platform) Authorized(ctx context.Context, req Request) (*Token, error) {
	// There's no policies yet. Just check if the token is valid.
	t, err := p.Introspect(ctx)
	if err != nil {
		return nil, err
	}

	// and just for safe keeping
	if t.ExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidToken
	}
	return t, nil
}

func (p *platform) Token() (*Token, error) {
	p.Lock()
	defer p.Unlock()

	// we should have cached the token and if it hasn't expired we'll hand it back
	if p.t != nil && len(p.t.AccessToken) > 0 && !p.t.ExpiresAt.Before(time.Now()) {
		return p.t, nil
	}

	var grantType, refreshToken string

	// if its nil, ask for new token
	if p.t == nil {
		grantType = "client_credentials"
	} else {
		// ask for refresh token
		grantType = "refresh_token"
		refreshToken = p.t.RefreshToken
	}

	// @todo Get Token

	// save token for reuse
	p.t = &Token{
		AccessToken:  "",
		RefreshToken: "",
		TokenType:    "",
		ExpiresAt:    time.Unix(3600, 0),
		//Scopes:       []string{},
		//Metadata:     "",
	}

	return p.t, nil
}

func (p *platform) Introspect(ctx context.Context) (*Token, error) {
	t, ok := p.FromContext(ctx)
	if !ok {
		md, kk := metadata.FromContext(ctx)
		if !kk {
			return nil, ErrInvalidToken
		}
		t, ok = p.FromHeader(md)
		if !ok {
			return nil, ErrInvalidToken
		}
	}

	// @todo INTROSPECT

	return &Token{
		AccessToken:  "",
		RefreshToken: "",
		TokenType:    "",
		ExpiresAt:    time.Unix(3600, 0),
		//Scopes:       "",
		//Metadata:     "",
	}, nil
}

func (p *platform) Revoke(t *Token) error {
	// @TODO revoke
	return nil
}

func (p *platform) FromContext(ctx context.Context) (*Token, bool) {
	t, ok := ctx.Value(tokenKey{}).(*Token)
	return t, ok
}

func (p *platform) NewContext(ctx context.Context, t *Token) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

func (p *platform) FromHeader(hd map[string]string) (*Token, bool) {
	t, ok := hd["authorization"]
	if !ok {
		return nil, false
	}
	parts := strings.Split(t, " ")
	if len(parts) != 2 {
		return nil, false
	}
	return &Token{
		AccessToken: parts[1],
		TokenType:   parts[0],
	}, true
}

func (p *platform) NewHeader(hd map[string]string, t *Token) map[string]string {
	// we basically only store access token
	hd["authorization"] = t.TokenType + " " + t.AccessToken
	return hd
}

func (p *platform) Start() error {
	p.Lock()
	defer p.Unlock()

	if p.running {
		return nil
	}

	p.exit = make(chan bool)
	p.running = true
	go p.run(p.exit)
	return nil
}

func (p *platform) Stop() error {
	p.Lock()
	defer p.Unlock()
	if !p.running {
		return nil
	}

	close(p.exit)
	p.exit = nil
	p.running = false
	return nil
}

func (p *platform) String() string {
	return "platform"
}
