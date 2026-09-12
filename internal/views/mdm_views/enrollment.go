package mdm_views

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"github.com/a-h/templ"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// EnrollmentQR encodes the invitation locally. Neither the link nor its token
// is sent to an image service. A four-module quiet zone keeps the code scannable.
func EnrollmentQR(invitationURL string) templ.SafeURL {
	code, err := qr.Encode(invitationURL, qr.M, qr.Auto)
	if err != nil {
		return ""
	}
	size := code.Bounds().Dx() * 6
	large, err := barcode.Scale(code, size, size)
	if err != nil {
		return ""
	}
	canvas := image.NewRGBA(image.Rect(0, 0, size+48, size+48))
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(canvas, image.Rect(24, 24, size+24, size+24), large, large.Bounds().Min, draw.Src)
	var data bytes.Buffer
	if err = png.Encode(&data, canvas); err != nil {
		return ""
	}
	return templ.SafeURL("data:image/png;base64," + base64.StdEncoding.EncodeToString(data.Bytes()))
}
