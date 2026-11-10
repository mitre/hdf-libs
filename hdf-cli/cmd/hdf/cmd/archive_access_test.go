package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchiveAccessCommands(t *testing.T) {
	for _, command := range []string{"convert", "evidence"} {
		t.Run(command, func(t *testing.T) {
			dir, pkg := bundleTree(t)
			var baseline []byte
			for _, policy := range []string{"private", "inherit"} {
				output := filepath.Join(dir, policy+".zip")
				args := []string{"evidence", "bundle", pkg}
				if command == "convert" {
					args = []string{"convert", "--bundle", bundleSourceFixture(t), "--to", "ecs"}
				}
				args = append(args, "--output-access", policy, "-o", output)
				_, _, err := executeCommand(args...)
				require.NoError(t, err)
				contents, err := os.ReadFile(output)
				require.NoError(t, err)
				if baseline == nil {
					baseline = contents
				} else {
					require.Equal(t, baseline, contents, "access policy must not change archive contents")
				}
				entries := zipEntries(t, output)
				input, entry := pkg, "pkg.json"
				if command == "convert" {
					input, entry = bundleSourceFixture(t), "source.json"
				}
				source, err := os.ReadFile(input)
				require.NoError(t, err)
				require.Equal(t, source, entries[entry])
			}
		})
	}
}

func TestArchiveAccessInvalidPolicyBeforeInput(t *testing.T) {
	for _, command := range []string{"convert", "evidence"} {
		for _, policy := range []string{"", "shared", "PRIVATE"} {
			t.Run(command+"/"+policy, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "missing.json")
				output := filepath.Join(dir, "existing.zip")
				sentinel := []byte("existing archive")
				require.NoError(t, os.WriteFile(output, sentinel, 0o600))
				args := []string{"evidence", "bundle", input}
				if command == "convert" {
					args = []string{"convert", "--bundle", input, "--to", "ecs"}
				}
				args = append(args, "--output-access="+policy, "--overwrite", "-o", output)
				_, _, err := executeCommand(args...)
				require.ErrorContains(t, err, "--output-access must be private or inherit")
				contents, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, sentinel, contents)
				files, err := os.ReadDir(dir)
				require.NoError(t, err)
				require.Len(t, files, 1, "invalid policy must not create a staged archive")
			})
		}
	}
}

func TestArchiveAccessRequiresBundle(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "export.zip")
	stdout, _, err := executeCommand("convert", "missing.json", "--output-access", "private", "-o", output)
	require.ErrorContains(t, err, "--output-access requires --bundle")
	require.Empty(t, stdout)
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, files, "invalid flags must not create output or staged files")
}

func TestArchiveAccessCollisionHandling(t *testing.T) {
	for _, scenario := range []string{"retry", "exhausted", "permission"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			calls := 0
			paths := map[string]bool{}
			file, err := createArchiveTempWithOpener(dir, archiveInherit, func(path string, access archiveAccess) (*os.File, error) {
				calls++
				require.Equal(t, archiveInherit, access)
				require.Equal(t, dir, filepath.Dir(path))
				require.False(t, paths[path], "retry must use a fresh name")
				paths[path] = true
				if scenario == "permission" {
					return nil, os.ErrPermission
				}
				if scenario == "retry" && calls == 2 {
					return openArchive(path, access)
				}
				return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrExist}
			})
			switch scenario {
			case "retry":
				require.NoError(t, err)
				require.NotNil(t, file)
				require.NoError(t, file.Close())
				require.Equal(t, 2, calls)
			case "exhausted":
				require.Nil(t, file)
				require.ErrorIs(t, err, os.ErrExist)
				require.Equal(t, 10, calls)
			case "permission":
				require.Nil(t, file)
				require.ErrorIs(t, err, os.ErrPermission)
				require.Equal(t, 1, calls)
			}
		})
	}
	file, err := createArchiveTemp(t.TempDir(), "unknown")
	require.Nil(t, file)
	require.ErrorContains(t, err, "invalid archive access policy")
}

func TestArchiveAccessWindowsExtendedNames(t *testing.T) {
	for _, prefix := range []string{`\??\C:\`, `\\?\C:\`, `//?/C:/`, `\\?\UNC\server\share\`} {
		t.Run(prefix, func(t *testing.T) {
			path := prefix + strings.Repeat(`directory\`, 30) + "archive.zip"
			got, err := archiveWindowsName(path, func(string) (string, error) {
				return "", fmt.Errorf("extended names must bypass Win32 full-path interpretation")
			})
			require.NoError(t, err)
			require.Equal(t, path, got)
		})
	}
}

func TestArchiveAccessWindowsOrdinaryNames(t *testing.T) {
	longSuffix := strings.Repeat(`directory\`, 30) + "archive.zip"
	for _, tc := range []struct{ name, resolved, want string }{
		{"short", `C:\dir\archive.zip`, `C:\dir\archive.zip`},
		{"long-drive", `C:\` + longSuffix, `\\?\C:\` + longSuffix},
		{"long-unc", `\\server\share\` + longSuffix, `\\?\UNC\server\share\` + longSuffix},
		{"device", `\\.\C:\` + longSuffix, `\\.\C:\` + longSuffix},
		{"resolved-extended", `\\?\C:\` + longSuffix, `\\?\C:\` + longSuffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			got, err := archiveWindowsName("archive.zip", func(path string) (string, error) {
				called = true
				require.Equal(t, "archive.zip", path)
				return tc.resolved, nil
			})
			require.NoError(t, err)
			require.True(t, called)
			require.Equal(t, tc.want, got)
		})
	}
	resolutionError := errors.New("path resolution failed")
	got, err := archiveWindowsName("archive.zip", func(string) (string, error) {
		return "", resolutionError
	})
	require.ErrorIs(t, err, resolutionError)
	require.Empty(t, got)
}
