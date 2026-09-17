// Package captcha issues and checks self-hosted image captcha challenges.
//
// It wraps github.com/mojocn/base64Captcha's digit-image driver behind two
// small, pluggable interfaces — Generator and Store — instead of building a
// challenge/response scheme from scratch. The package knows nothing about who
// is solving a challenge: a caller that needs to bind a challenge to a
// request, a session or a rate-limit key does so on its own side, by holding
// on to the opaque Challenge.ID it gets back from Generate. This package only
// ever sees ids and answers.
//
// A challenge is single-use: once Verify has been called for an id, that id
// can never be verified again, whether the answer was right or wrong. This is
// what makes a captcha resistant to being brute-forced — an attacker gets
// exactly one guess per issued challenge, not unlimited guesses against one
// image.
//
// This file covers only "generate an id and an image" / "check an id and an
// answer" — the self-hosted image captcha. Verifying a third-party token
// captcha (Cloudflare Turnstile, Google reCAPTCHA, hCaptcha) is a different
// mechanism — an HTTP call to that provider's siteverify endpoint, plus
// hostname pinning against the result — and lives alongside this in
// token.go, as TokenVerifier. The two share a package because they are both
// "captcha verification" from a caller's point of view, but neither depends
// on the other's types.
package captcha

import (
	"fmt"

	base64Captcha "github.com/mojocn/base64Captcha"
)

// Challenge is an issued, unsolved captcha: an opaque id and a ready-to-embed
// image. It carries no information about who requested it or what it will be
// used for.
type Challenge struct {
	// ID identifies this challenge to a later Verify call. Treat it as
	// opaque; its format is not part of this package's API.
	ID string
	// Image is a "data:image/...;base64,..." URL, ready for an <img src>.
	Image string
}

// Generator issues challenges and checks answers against them.
//
// Implementations must make Verify single-use: once an id has been checked —
// whether the answer was correct or not — a later call with the same id must
// return false. Implementations must also be safe for concurrent use, since a
// captcha is typically issued and verified from concurrent HTTP handlers.
type Generator interface {
	// Generate creates and stores a new challenge.
	Generate() (Challenge, error)
	// Verify reports whether answer is correct for the challenge identified
	// by id. It consumes the challenge: a repeat call with the same id
	// always returns false afterward, regardless of the answer given either
	// time. An empty id or answer is always false and never touches the
	// store.
	Verify(id, answer string) bool
}

// driverParams are the digit-image driver's tuning knobs, exposed only
// through WithDriverParams so the zero value of ImageGenerator is never used
// directly.
type driverParams struct {
	height, width, length int
	maxSkew               float64
	dotCount              int
}

// defaultDriverParams matches the digit captcha both source projects issued:
// a 5-digit code (digits avoid the 0/O and 1/l ambiguity letters have) drawn
// at 80x240 with a 0.7 max skew and 80 background dots.
var defaultDriverParams = driverParams{height: 80, width: 240, length: 5, maxSkew: 0.7, dotCount: 80}

// Option configures an ImageGenerator.
type Option func(*imageGeneratorConfig)

type imageGeneratorConfig struct {
	driver base64Captcha.Driver
}

// WithDriverParams overrides the digit-image driver's size and noise
// parameters. Unset, an ImageGenerator draws the same 80x240, 5-digit,
// 0.7-skew, 80-dot image both source projects used.
func WithDriverParams(height, width, length int, maxSkew float64, dotCount int) Option {
	return func(c *imageGeneratorConfig) {
		c.driver = base64Captcha.NewDriverDigit(height, width, length, maxSkew, dotCount)
	}
}

// WithDriver replaces the captcha driver entirely, e.g. to switch from digits
// to base64Captcha's arithmetic, Chinese-character or audio drivers. It takes
// a base64Captcha.Driver directly, so a caller reaching for this needs the
// base64Captcha import too; ImageGenerator's own exported API never requires
// it.
func WithDriver(driver base64Captcha.Driver) Option {
	return func(c *imageGeneratorConfig) { c.driver = driver }
}

// ImageGenerator is the default Generator: a self-hosted, drawn image
// captcha with no external calls. Zero external calls also means it works
// unchanged behind a network that cannot reach a third-party captcha
// provider.
type ImageGenerator struct {
	driver base64Captcha.Driver
	store  Store
}

var _ Generator = (*ImageGenerator)(nil)

// NewImageGenerator builds an ImageGenerator over store. A nil store is
// replaced with DefaultMemoryStore(), a TTL- and capacity-bounded in-process
// store; pass a different Store (e.g. a Redis-backed one) to share challenges
// across multiple instances of a caller's service.
func NewImageGenerator(store Store, opts ...Option) *ImageGenerator {
	if store == nil {
		store = DefaultMemoryStore()
	}
	cfg := imageGeneratorConfig{
		driver: base64Captcha.NewDriverDigit(
			defaultDriverParams.height,
			defaultDriverParams.width,
			defaultDriverParams.length,
			defaultDriverParams.maxSkew,
			defaultDriverParams.dotCount,
		),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &ImageGenerator{driver: cfg.driver, store: store}
}

// Generate implements Generator. Each call draws a fresh image and id; the
// underlying driver generates the id, so concurrent calls never collide on
// one.
func (g *ImageGenerator) Generate() (Challenge, error) {
	c := base64Captcha.NewCaptcha(g.driver, g.store)
	id, b64s, _, err := c.Generate()
	if err != nil {
		return Challenge{}, fmt.Errorf("captcha: generate: %w", err)
	}
	return Challenge{ID: id, Image: b64s}, nil
}

// Verify implements Generator.
func (g *ImageGenerator) Verify(id, answer string) bool {
	if id == "" || answer == "" {
		return false
	}
	// clear=true: the challenge is consumed by this call, correct or not, so
	// it can never be checked a second time.
	return g.store.Verify(id, answer, true)
}
