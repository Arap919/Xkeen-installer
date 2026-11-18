module github.com/Arap919/xkeen-installer

go 1.26.0

// Local delta: atomic SMB rename with ReplaceIfExists=0; see third_party/go-smb2/UPSTREAM.json.
replace github.com/cloudsoda/go-smb2 => ./third_party/go-smb2

require (
	github.com/cloudsoda/go-smb2 v0.0.0-20260609183447-7b96c35f5f4b
	github.com/pkg/sftp v1.13.9
	github.com/sergeymakinen/go-crypt v1.0.6
	github.com/wailsapp/wails/v2 v2.17.1
	golang.org/x/crypto v0.59.0
	golang.org/x/sys v0.50.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	git.sr.ht/~jackmordaunt/go-toast/v2 v2.0.3 // indirect
	github.com/bep/debounce v1.2.1 // indirect
	github.com/cloudsoda/sddl v0.0.0-20250224235906-926454e91efc // indirect
	github.com/gabriel-vasile/mimetype v1.4.16 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jchv/go-winloader v0.0.0-20210711035445-715c2860da7e // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/labstack/echo/v4 v4.16.1 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/leaanthony/go-ansi-parser v1.6.1 // indirect
	github.com/leaanthony/gosod v1.0.4 // indirect
	github.com/leaanthony/slicer v1.6.0 // indirect
	github.com/leaanthony/u v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/samber/lo v1.49.1 // indirect
	github.com/tkrajina/go-reflector v0.5.8 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/wailsapp/go-webview2 v1.0.22 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
