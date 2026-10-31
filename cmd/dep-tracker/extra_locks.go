package main

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

func parsePubspecLock(path, content string) ([]Package, error) {
	var pkgs []Package
	var name, version, source string
	flush := func() error {
		if name == "" || source == "sdk" {
			return nil
		}
		if version == "" {
			return fmt.Errorf("missing locked version for %s in %s", name, path)
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "Pub", ManifestPath: path})
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	inPackages := false
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if trim == "packages:" {
			inPackages = true
			continue
		}
		if !strings.HasPrefix(line, " ") {
			if inPackages {
				if err := flush(); err != nil {
					return pkgs, err
				}
				name = ""
			}
			inPackages = false
			continue
		}
		if !inPackages {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trim, ":") {
			if err := flush(); err != nil {
				return pkgs, err
			}
			name = strings.Trim(strings.TrimSuffix(trim, ":"), `"'`)
			version = ""
			source = ""
			continue
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
			key, value, ok := strings.Cut(trim, ":")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			switch key {
			case "version":
				version = value
			case "source":
				source = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, err
	}
	if err := flush(); err != nil {
		return pkgs, err
	}
	return pkgs, nil
}

var mixHexLockRE = regexp.MustCompile(`(?m)"([^"\n]+)"\s*:\s*\{\s*:hex\s*,\s*:([a-zA-Z0-9_]+)\s*,\s*"([^"\n]+)"`)

func parseMixLock(path, content string) ([]Package, error) {
	var pkgs []Package
	for _, m := range mixHexLockRE.FindAllStringSubmatch(content, -1) {
		pkgs = append(pkgs, Package{Name: m[2], Version: m[3], Ecosystem: "Hex", ManifestPath: path})
	}
	if len(pkgs) == 0 && strings.TrimSpace(content) != "%{}" {
		return nil, fmt.Errorf("no supported Hex lock entries in %s", path)
	}
	return pkgs, nil
}

func unquotedBracketDelta(line string) int {
	depth := 0
	var quote rune
	escaped := false
	for _, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '[' {
			depth++
		}
		if r == ']' {
			depth--
		}
	}
	return depth
}
