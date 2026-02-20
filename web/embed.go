package web

import "embed"

//go:embed index.html setup.html css/* js/* fonts/* vendor/* partials/*
var Assets embed.FS
