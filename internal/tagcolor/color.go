// Package tagcolor preserves the original console palette and bounded custom
// colors without treating stored tag metadata as CSS or a generated class name.
package tagcolor

import (
	"math"
	"strconv"
	"strings"
)

// The values match the original bg-*-500 rules in assets/css/main.css.
var palette = map[string]string{
	"red": "#ef4444", "orange": "#f97316", "amber": "#f59e0b", "yellow": "#eab308",
	"lime": "#84cc16", "green": "#22c55e", "emerald": "#10b981", "teal": "#14b8a6",
	"cyan": "#06b6d4", "sky": "#0ea5e9", "blue": "#3b82f6", "indigo": "#6366f1",
	"violet": "#8b5cf6", "purple": "#a855f7", "fuchsia": "#d946ef", "pink": "#ec4899",
	"rose": "#f43f5e", "gray": "#6b7280", "stone": "#78716c",
}

func Names() []string {
	return []string{"red", "orange", "amber", "yellow", "lime", "green", "emerald", "teal", "cyan", "sky", "blue", "indigo", "violet", "purple", "fuchsia", "pink", "rose", "gray", "stone"}
}

func IsHex(value string) bool {
	if len(value) != 7 || value[0] != '#' {
		return false
	}
	for _, c := range value[1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func Valid(value string) bool { _, ok := palette[value]; return ok || IsHex(value) }

func Background(value string) string {
	if hex, ok := palette[value]; ok {
		return hex
	}
	if IsHex(value) {
		return strings.ToLower(value)
	}
	return palette["gray"]
}

// Choose the stronger black/white contrast for the resolved, opaque sRGB color.
func Foreground(value string) string {
	hex := Background(value)
	linear := func(start int) float64 {
		n, _ := strconv.ParseUint(hex[start:start+2], 16, 8)
		v := float64(n) / 255
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	luminance := 0.2126*linear(1) + 0.7152*linear(3) + 0.0722*linear(5)
	if (luminance+0.05)/0.05 >= 1.05/(luminance+0.05) {
		return "#000000"
	}
	return "#ffffff"
}
