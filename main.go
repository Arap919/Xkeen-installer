package main

import (
	"context"
	"embed"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"log"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := newApp()
	err := wails.Run(&options.App{Title: "XKeen Installer", Width: 1120, Height: 820, MinWidth: 760, MinHeight: 640, AssetServer: &assetserver.Options{Assets: assets}, Bind: []interface{}{app}, OnStartup: func(ctx context.Context) {
		app.ctx = ctx
		app.emit = func(p Progress) { wailsruntime.EventsEmit(ctx, "install:progress", p) }
	}, OnShutdown: func(context.Context) { app.CancelInstall() }})
	if err != nil {
		log.Print("Desktop application failed to start")
	}
}
