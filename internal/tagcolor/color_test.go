package tagcolor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestPalettePreservesExistingConsoleColors(t *testing.T) {
	css, err := os.ReadFile("../../assets/css/main.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		rule := regexp.MustCompile(`(?s)\.bg-` + name + `-500\s*\{[^}]*rgb\((\d+) (\d+) (\d+) /`).FindSubmatch(css)
		if len(rule) != 4 {
			t.Fatal("existing palette rule missing", name)
		}
		values := make([]int, 3)
		for i := range values {
			values[i], err = strconv.Atoi(string(rule[i+1]))
			if err != nil {
				t.Fatal(err)
			}
		}
		want := fmt.Sprintf("#%02x%02x%02x", values[0], values[1], values[2])
		if !Valid(name) || Background(name) != want {
			t.Fatal("legacy color changed", name, Background(name), want)
		}
	}
}

func TestCustomColorsAndUntrustedLegacyFallback(t *testing.T) {
	for _, value := range []string{"", "transparent", "Red", "#fff", "#1234567", "#gggggg", "red; background:url(https://outside.example.test)", "#ffffff\n"} {
		if Valid(value) || Background(value) != "#6b7280" {
			t.Fatal("untrusted CSS accepted", value)
		}
	}
	if !Valid("#AbC123") || Background("#AbC123") != "#abc123" {
		t.Fatal("custom color lost")
	}
	if Foreground("#ffffff") != "#000000" || Foreground("#000000") != "#ffffff" || Foreground("yellow") != "#000000" {
		t.Fatal("foreground contrast is unsuitable")
	}
}
