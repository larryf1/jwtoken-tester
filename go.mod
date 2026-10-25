module github.com/larryf1/jwtoken-tester

go 1.27.3

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/lestrrat-go/jwx/v4 v4.6.0
	golang.org/x/time v0.16.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/conventionalcommit/commitlint v0.12.0 // indirect
	github.com/conventionalcommit/parser v0.8.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/urfave/cli/v2 v2.27.7 // indirect
	github.com/xrash/smetrics v0.0.0-20261013231157-39c47d93efba // indirect
	golang.org/x/mod v0.42.0 // indirect
)

replace github.com/conventionalcommit/parser => ./third_party/conventionalcommit-parser

tool github.com/conventionalcommit/commitlint
