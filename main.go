package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/labstack/echo"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/netauth/netauth/pkg/netauth"
	_ "github.com/netauth/netauth/pkg/netauth/memory"
)

var (
	cfg = pflag.String("config", "", "Config file")

	rpc *netauth.Client
)

func init() {
	viper.SetDefault("authserver.bind", "localhost")
	viper.SetDefault("authserver.port", 8081)
}

func authHeader(ctx context.Context, h string) error {
	switch {
	case strings.Contains(strings.ToLower(h), "basic"):
		if len(strings.Fields(h)) != 2 {
			return errors.New("Malformed header")
		}
		credstr := strings.Fields(h)[1]
		credbytes, err := base64.StdEncoding.DecodeString(credstr)
		if err != nil {
			return errors.New("Base64 decode error")
		}
		credstr = string(credbytes[:])

		creds := strings.SplitN(credstr, ":", 2)
		return rpc.AuthEntity(ctx, creds[0], creds[1])
	}
	return nil
}

func httpAuthAny(c echo.Context) error {
	hdr := c.Request().Header.Get("Authorization")
	if hdr == "" {
		return c.NoContent(http.StatusUnauthorized)
	}
	if err := authHeader(c.Request().Context(), hdr); err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}
	return c.NoContent(http.StatusNoContent)
}

func main() {
	appLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "authserver",
		Level: hclog.LevelFromString("TRACE"),
	})
	hclog.SetDefault(appLogger)

	viper.BindPFlags(pflag.CommandLine)
	if *cfg != "" {
		viper.SetConfigFile(*cfg)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.netauth")
		viper.AddConfigPath("/etc/netauth/")
	}
	if err := viper.ReadInConfig(); err != nil {
		appLogger.Error("Error reading config", "error", err)
		os.Exit(1)
	}
	viper.Set("client.ServiceName", "authserver")

	var err error
	rpc, err = netauth.New()
	if err != nil {
		appLogger.Info("Error during client initialization", "error", err)
		os.Exit(1)
	}

	e := echo.New()
	e.GET("/auth/any", httpAuthAny)
	err = e.Start(viper.GetString("authserver.bind") + ":" + viper.GetString("authserver.port"))
	appLogger.Error("Terminal error from webserver", "error", err)
}
