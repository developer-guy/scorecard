// Copyright 2020 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package roundtripper has implementations of http.RoundTripper useful to clients.RepoClient.
package roundtripper

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"go.uber.org/zap"
)

// githubAuthTokens are for making requests to GiHub's API.
var githubAuthTokens = []string{"GITHUB_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GH_AUTH_TOKEN"}

const (
	// githubAppKeyPath is the path to file for GitHub App key.
	githubAppKeyPath = "GITHUB_APP_KEY_PATH"
	// githubAppID is the app ID for the GitHub App.
	githubAppID = "GITHUB_APP_ID"
	// githubAppInstallationID is the installation ID for the GitHub App.
	githubAppInstallationID = "GITHUB_APP_INSTALLATION_ID"
	// githubSecretServer is the RPC URL for the secret server.
	githubSecretServer = "GITHUB_SECRET_SERVER"
)

func readGitHubTokens() (string, bool) {
	for _, name := range githubAuthTokens {
		if token, exists := os.LookupEnv(name); exists && token != "" {
			return token, exists
		}
	}
	return "", false
}

// NewTransport returns a configured http.Transport for use with GitHub.
func NewTransport(ctx context.Context, logger *zap.SugaredLogger) http.RoundTripper {
	transport := http.DefaultTransport

	// nolint
	if token, exists := readGitHubTokens(); exists {
		// Use GitHub PAT
		transport = makeGitHubTransport(transport, makeTokenAccessor(strings.Split(token, ",")))
	} else if keyPath := os.Getenv(githubAppKeyPath); keyPath != "" { // Also try a GITHUB_APP
		appID, err := strconv.Atoi(os.Getenv(githubAppID))
		if err != nil {
			log.Panic(err)
		}
		installationID, err := strconv.Atoi(os.Getenv(githubAppInstallationID))
		if err != nil {
			log.Panic(err)
		}
		transport, err = ghinstallation.NewKeyFromFile(transport, int64(appID), int64(installationID), keyPath)
		if err != nil {
			log.Panic(err)
		}
	} else if secretServer := os.Getenv(githubSecretServer); secretServer != "" {
		transport = makeGitHubTransport(transport, makeRPCAccessor(secretServer))
	} else {
		log.Fatalf("GitHub token env var is not set. " +
			"Please read https://github.com/ossf/scorecard#authentication")
	}

	return MakeCensusTransport(MakeRateLimitedTransport(transport, logger))
}
