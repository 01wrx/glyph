package main

import (
	"flag"
	"io"
	"os"
	"os/signal"

	"glyph/app"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mailbox" {
		runMailbox()
		return
	}
	a, err := app.Open(app.DefaultHome())
	if err != nil {
		os.Exit(1)
	}
	defer a.Close()
	addr, err := a.Listen(os.Getenv("GLYPH_LISTEN"))
	if err != nil {
		os.Exit(1)
	}
	url := "http://" + addr + "/?t=" + a.Token()
	if os.Getenv("GLYPH_NO_WINDOW") == "1" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		return
	}
	openWindow(url)
}

func runMailbox() {
	fs := flag.NewFlagSet("mailbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	owner := fs.String("owner", "", "")
	addr := fs.String("addr", "", "")
	if err := fs.Parse(os.Args[2:]); err != nil || *dir == "" || *owner == "" || *addr == "" {
		os.Exit(2)
	}
	if err := app.RunMailbox(*dir, *owner, *addr); err != nil {
		os.Exit(1)
	}
}
