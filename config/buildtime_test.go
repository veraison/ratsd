// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildVersion(test *testing.T) {
	test.Setenv("RATSD_BUILD_VERSION", "")
	sourceDir := test.TempDir()
	scriptPath := filepath.Join(sourceDir, "scripts", "get-ratsd-version")
	script, err := os.ReadFile("../scripts/get-ratsd-version")
	require.NoError(test, err)
	require.NoError(test, os.MkdirAll(filepath.Dir(scriptPath), 0755))
	require.NoError(test, os.WriteFile(scriptPath, script, 0600))

	readVersion := func(test *testing.T) string {
		test.Helper()
		command := exec.Command("sh", scriptPath)
		output, err := command.CombinedOutput()
		require.NoError(test, err, string(output))
		return strings.TrimSpace(string(output))
	}

	assert.Equal(test, "0.0.0-unknown", readVersion(test))
	test.Run("explicit version without Git metadata", func(test *testing.T) {
		test.Setenv("RATSD_BUILD_VERSION", "1.2.3-release")
		assert.Equal(test, "1.2.3-release", readVersion(test))
	})

	if _, err := exec.LookPath("git"); err != nil {
		test.Skip("Git is required to test version detection from repository metadata")
	}
	runGit := func(args ...string) string {
		test.Helper()
		options := []string{
			"-C", sourceDir,
			"-c", "user.name=RATSD tests",
			"-c", "user.email=tests@example.invalid",
			"-c", "commit.gpgsign=false",
			"-c", "tag.gpgsign=false",
			"-c", "core.hooksPath=",
		}
		command := exec.Command("git", append(options, args...)...)
		output, err := command.CombinedOutput()
		require.NoError(test, err, string(output))
		return strings.TrimSpace(string(output))
	}

	runGit("init", "--quiet")
	assert.Equal(test, "0.0.0-unknown", readVersion(test))
	runGit("commit", "--quiet", "--allow-empty", "-m", "Test version detection")
	commit := runGit("rev-parse", "--short", "HEAD")
	assert.Equal(test, "0.0.0+"+commit, readVersion(test))

	runGit("tag", "v1.9.0")
	runGit("tag", "v1.10.0")
	runGit("tag", "unrelated-release")
	assert.Equal(test, "1.10.0+"+commit, readVersion(test))
	test.Run("Git unavailable", func(test *testing.T) {
		binaryDir := test.TempDir()
		for _, name := range []string{"sh", "dirname"} {
			path, err := exec.LookPath(name)
			require.NoError(test, err)
			require.NoError(test, os.Symlink(path, filepath.Join(binaryDir, name)))
		}
		test.Setenv("PATH", binaryDir)
		assert.Equal(test, "0.0.0-unknown", readVersion(test))
	})
	test.Setenv("RATSD_BUILD_VERSION", "2.0.0")
	assert.Equal(test, "2.0.0", readVersion(test))
}
