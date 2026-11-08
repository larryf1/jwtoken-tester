package server

// IndexResponse is the response body for the service index endpoint.
type IndexResponse struct {
	Service   string   `json:"service" example:"jwtoken-tester"`
	Version   string   `json:"version" example:"1.0.0"`
	Warning   string   `json:"warning" example:"integration-test token issuer; ephemeral in-memory keys"`
	Endpoints []string `json:"endpoints" example:"GET /healthz,GET /version,GET /.well-known/jwks.json"`
}

// HealthResponse is the response body for the health check endpoint.
type HealthResponse struct {
	Status     string            `json:"status" enum:"ok" example:"ok"`
	Version    string            `json:"version" example:"1.0.0"`
	Warning    string            `json:"warning" example:"test issuer: keys are ephemeral and in-memory; do not use in production"`
	Algorithms []string          `json:"algorithms" enum:"RS256,ES256,EdDSA" example:"RS256,ES256,EdDSA"`
	ActiveKids map[string]string `json:"active_kids,omitempty" example:"RS256:abc123...,ES256:def456..."`
}

// VersionResponse is the response body for the version endpoint.
type VersionResponse struct {
	Version string `json:"version" example:"1.0.0"`
}

// JWKS is the JSON Web Key Set response.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty,omitempty" enum:"RSA,EC,OKP" description:"Key type"`
	Use string `json:"use,omitempty" enum:"sig" description:"Key usage (signature)"`
	Alg string `json:"alg,omitempty" enum:"RS256,ES256,EdDSA" description:"Algorithm"`
	Kid string `json:"kid,omitempty" description:"RFC 7638 thumbprint-derived Key ID"`
	N   string `json:"n,omitempty" description:"RSA modulus (for RSA keys)"`
	E   string `json:"e,omitempty" description:"RSA public exponent (for RSA keys)"`
	Crv string `json:"crv,omitempty" enum:"P-256,Ed25519" description:"Curve (for EC/OKP keys)"`
	X   string `json:"x,omitempty" description:"X coordinate (for EC/OKP keys)"`
	Y   string `json:"y,omitempty" description:"Y coordinate (for EC keys)"`
}

// DiscoveryResponse is the shared metadata document for OIDC and OAuth discovery.
type DiscoveryResponse struct {
	Issuer                            string   `json:"issuer,omitempty" format:"uri" example:"http://127.0.0.1:8080"`
	JwksURI                           string   `json:"jwks_uri,omitempty" format:"uri" example:"http://127.0.0.1:8080/.well-known/jwks.json"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty" format:"uri" description:"Always <issuer>/oauth/token" example:"http://127.0.0.1:8080/oauth/token"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty" format:"uri" description:"Always <issuer>/introspect" example:"http://127.0.0.1:8080/introspect"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty" example:"public"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty" enum:"RS256,ES256,EdDSA" example:"RS256,ES256,EdDSA"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty" example:"client_credentials"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty" enum:"client_secret_basic,client_secret_post,none" example:"client_secret_basic,client_secret_post,none"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty" example:"token"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty" example:"iss,sub,aud,exp,nbf,iat,jti,scope,client_id"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty" description:"Present only when SCOPES is configured" example:"read,write"`
}

// TokenRequest is the request body for POST /token.
type TokenRequest struct {
	Claims  map[string]any `json:"claims,omitempty" description:"Arbitrary claim set; standard claims included" example:"sub:user-123,aud:my-service" swaggertype:"object,string"`
	Alg     string         `json:"alg,omitempty" enum:"RS256,ES256,EdDSA" description:"Signing algorithm (must be enabled)" example:"RS256"`
	Headers map[string]any `json:"headers,omitempty" description:"Extra protected JOSE header parameters to embed" example:"x-test-harness:run-7" swaggertype:"object,string"`
}

// TokenResponse is the response body for token minting endpoints.
type TokenResponse struct {
	AccessToken string `json:"access_token" description:"JWT in JWS Compact Serialization" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."`
	TokenType   string `json:"token_type" enum:"Bearer" example:"Bearer"`
	ExpiresIn   int64  `json:"expires_in" description:"Token lifetime in seconds" example:"3600"`
}

// OAuthTokenRequest is the request body for POST /oauth/token (form-urlencoded).
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type" enum:"client_credentials" description:"Only client_credentials is supported" example:"client_credentials"`
	ClientID     string `json:"client_id,omitempty" description:"Client identifier used for sub and client_id. Required unless supplied with HTTP Basic authentication" example:"test-client"`
	ClientSecret string `json:"client_secret,omitempty" description:"Accepted for compatibility but never validated by this test issuer" example:"ignored"`
	Scope        string `json:"scope,omitempty" description:"Space-delimited scopes; whitespace is normalized and echoed back" example:"read write"`
	Alg          string `json:"alg,omitempty" enum:"RS256,ES256,EdDSA" description:"Enabled signing algorithm; defaults to RS256 when enabled, else the first enabled algorithm" example:"ES256"`
	TTL          string `json:"ttl,omitempty" description:"Non-negative Go duration capped by MAX_TTL" example:"5m"`
}

// OAuthTokenResponse is the response body for POST /oauth/token.
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token" description:"JWT in JWS Compact Serialization" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."`
	TokenType   string `json:"token_type" enum:"Bearer" example:"Bearer"`
	ExpiresIn   int64  `json:"expires_in" description:"Token lifetime in seconds" example:"3600"`
	Scope       string `json:"scope,omitempty" description:"Normalized scope, present only when requested" example:"read write"`
}

// OAuthErrorResponse is the error response body for OAuth endpoints.
type OAuthErrorResponse struct {
	Error            string `json:"error" description:"Standard OAuth error code" example:"invalid_request"`
	ErrorDescription string `json:"error_description,omitempty" description:"Human-readable error message" example:"grant_type is required"`
}

// IntrospectionRequest is the request body for POST /introspect (form-urlencoded).
type IntrospectionRequest struct {
	Token         string `json:"token" description:"JWT in JWS Compact Serialization" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."`
	TokenTypeHint string `json:"token_type_hint,omitempty" description:"Accepted and ignored" example:"access_token"`
}

// IntrospectionResponse is the response body for POST /introspect.
type IntrospectionResponse struct {
	Active    bool   `json:"active" example:"true"`
	TokenType string `json:"token_type,omitempty" enum:"Bearer" description:"Present only for active tokens" example:"Bearer"`
	Scope     string `json:"scope,omitempty" description:"Present only when the token carries a scope claim" example:"read write"`
}

// VerifyRequest is the request body for POST /verify.
type VerifyRequest struct {
	Token  string    `json:"token" description:"JWT in JWS Compact Serialization" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."`
	Aud    audience  `json:"aud,omitempty" description:"Expected audience; a match against any member passes" swaggerignore:"true"`
	Alg    *[]string `json:"alg,omitempty" minItems:"1" description:"Non-empty subset of enabled algorithms to accept" example:"RS256"`
	Leeway string    `json:"leeway,omitempty" description:"Go duration widening the exp/nbf/iat window" example:"30s"`
}

// VerifyResponse is the response body for POST /verify.
type VerifyResponse struct {
	Valid            bool           `json:"valid"`
	Reason           string         `json:"reason,omitempty" enum:"malformed,alg,kid,signature,expired,not_yet_valid,issuer,audience" description:"Closed failure reason; absent when valid"`
	Error            string         `json:"error,omitempty" description:"Human-readable failure message; absent when valid"`
	Header           map[string]any `json:"header,omitempty" description:"Decoded JOSE header" swaggertype:"object,string"`
	Claims           map[string]any `json:"claims,omitempty" description:"Token claims, present only after signature verification succeeded" swaggertype:"object,string"`
	UnverifiedClaims map[string]any `json:"unverified_claims,omitempty" description:"Token claims parsed before signature verification; never present with claims" swaggertype:"object,string"`
	Kid              string         `json:"kid,omitempty" description:"Key ID from the token header, when readable"`
	KidStatus        string         `json:"kid_status,omitempty" enum:"active,retired,unknown" description:"Whether the token's key is active, retired inside its grace window, or absent"`
	Alg              string         `json:"alg,omitempty" description:"Algorithm from the token header, when readable"`
}

// ErrorResponse is the generic error response body.
type ErrorResponse struct {
	Error string `json:"error" example:"unsupported algorithm"`
}
