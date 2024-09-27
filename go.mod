module gitea.com/actions/release-action

go 1.22.0

toolchain go1.23.1

require (
	code.gitea.io/sdk/gitea v0.15.1
	github.com/hashicorp/go-version v1.7.0
	github.com/sethvargo/go-githubactions v1.1.0
)

require github.com/sethvargo/go-envconfig v0.8.0 // indirect
