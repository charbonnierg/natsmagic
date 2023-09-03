package magicopts

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	// import the API like this
	"github.com/caddyserver/certmagic"
	"github.com/charbonnierg/azure"
	"github.com/charbonnierg/natsmagic/magicrepo"
	"github.com/charbonnierg/natsmagic/natslogger"
	"github.com/charbonnierg/prometheus-nats-exporter/collector"
	"github.com/charbonnierg/prometheus-nats-exporter/exporter"
	"github.com/libdns/digitalocean"
	"github.com/libdns/route53"
	"github.com/nats-io/nats-server/v2/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New() (*NatsMagic, error) {
	opts := &NatsMagic{
		LetsEncryptEmail:                   os.Getenv("NATS_MAGIC_EMAIL"),
		LetsEncryptCA:                      os.Getenv("NATS_MAGIC_CA"),
		LetsEncryptDnsProvider:             NewDnsProviderFromString(os.Getenv("NATS_MAGIC_PROVIDER")),
		LetsEncryptDnsSkipPropagationCheck: getBoolEnv("NATS_MAGIC_SKIP_DNS_PROPAGATION_CHECK"),
		LetsEncryptDnsPropagationDelay:     getIntegerEnv("NATS_MAGIC_DNS_PROPAGATION_DELAY"),
		LetsEncryptDnsPropagationTimeout:   getIntegerEnv("NATS_MAGIC_DNS_PROPAGATION_TIMEOUT"),
		LetsEncryptDnsChallengeTTL:         getIntegerEnv("NATS_MAGIC_DNS_CHALLENGE_TTL"),
		LetsEncryptDnsResolvers:            getCommaSeparateEnv("NATS_MAGIC_DNS_RESOLVERS"),
		DefaultDomains:                     getCommaSeparateEnv("NATS_MAGIC_DOMAINS"),
		StandardDomains:                    getCommaSeparateEnv("NATS_MAGIC_STANDARD_DOMAINS"),
		LeafnodeDomains:                    getCommaSeparateEnv("NATS_MAGIC_LEAFNODE_DOMAINS"),
		MonitoringDomains:                  getCommaSeparateEnv("NATS_MAGIC_MONITORING_DOMAINS"),
		WebsocketDomains:                   getCommaSeparateEnv("NATS_MAGIC_WEBSOCKET_DOMAINS"),
		MQTTDomains:                        getCommaSeparateEnv("NATS_MAGIC_MQTT_DOMAINS"),
		LoggingPreset:                      os.Getenv("NATS_LOGGING_PRESET"),
	}
	magicOptsUrl := os.Getenv("NATS_MAGIC_URL")
	if magicOptsUrl != "" {
		err := readNatsMagicFromUrl(magicOptsUrl, opts)
		if err != nil {
			return nil, err
		}
	}
	magicOptsFile := os.Getenv("NATS_MAGIC_FILE")
	if magicOptsFile != "" {
		err := readNatsMagicFromFile(magicOptsFile, opts)
		if err != nil {
			return nil, err
		}
	}
	opts.SetDefaultValues()
	err := opts.unsafeUpdateNatsConfig()
	if err != nil {
		return nil, err
	}
	err = opts.unsafeUpdateDnsAuth()
	if err != nil {
		return nil, err
	}
	return opts, nil
}

type NatsExporterFeatures struct {
	Varz          bool `json:"varz"`
	Connz         bool `json:"connz"`
	ConnzDetailed bool `json:"connz_detailed"`
	Subz          bool `json:"subz"`
	Routez        bool `json:"routez"`
	Healthz       bool `json:"healthz"`
	Gatewayz      bool `json:"gatewayz"`
	Leafz         bool `json:"leafz"`
}
type NatsExporterOptions struct {
	Host     string                `json:"host"`
	Port     int                   `json:"port"`
	Features *NatsExporterFeatures `json:"features"`
}

type NatsConfig = map[string]interface{}

type NatsMagic struct {
	logger          *zap.Logger
	atom            *zap.AtomicLevel
	remoteUserCreds map[string]string
	// Nats server options
	NatsConfig         NatsConfig           `json:"nats"`
	NatsExporterConfig *NatsExporterOptions `json:"nats_exporter"`
	LoggingPreset      string               `json:"logging_preset"`
	// LetsEncrypt options
	LetsEncryptEmail                   string            `json:"letsencrypt_email"`
	LetsEncryptCA                      string            `json:"letsencrypt_ca"`
	LetsEncryptDnsProvider             DnsProvider       `json:"letsencrypt_dns_provider"`
	LetsEncryptDataDir                 string            `json:"letsencrypt_data_dir"`
	LetsEncryptDnsSkipPropagationCheck bool              `json:"letsencrypt_dns_skip_propagation_check"`
	LetsEncryptDnsPropagationDelay     int               `json:"letsencrypt_dns_propagation_delay"`
	LetsEncryptDnsPropagationTimeout   int               `json:"letsencrypt_dns_propagation_timeout"`
	LetsEncryptDnsChallengeTTL         int               `json:"letsencrypt_dns_challenge_ttl"`
	LetsEncryptDnsResolvers            []string          `json:"letsencrypt_dns_resolvers"`
	LetsEncryptDnsAuth                 map[string]string `json:"letsencrypt_dns_auth"`
	// Global options
	DefaultDomains    []string               `json:"domains"`
	StandardDomains   []string               `json:"standard_domains"`
	LeafnodeDomains   []string               `json:"leafnode_domains"`
	MonitoringDomains []string               `json:"monitoring_domains"`
	WebsocketDomains  []string               `json:"websocket_domains"`
	MQTTDomains       []string               `json:"mqtt_domains"`
	RemoteUsers       map[string]*RemoteUser `json:"remote_users"`
}

func (o *NatsMagic) Enabled() bool {
	return len(o.DefaultDomains) > 0
}

func (o *NatsMagic) ExporterEnabled() bool {
	return o.NatsExporterConfig != nil
}

func (o *NatsMagic) SetDefaultValues() *NatsMagic {
	if len(o.StandardDomains) == 0 {
		o.StandardDomains = append(o.StandardDomains, o.DefaultDomains...)
	}
	if len(o.MonitoringDomains) == 0 {
		o.MonitoringDomains = append(o.MonitoringDomains, o.DefaultDomains...)
	}
	if len(o.WebsocketDomains) == 0 {
		o.WebsocketDomains = append(o.WebsocketDomains, o.DefaultDomains...)
	}
	if len(o.MQTTDomains) == 0 {
		o.MQTTDomains = append(o.MQTTDomains, o.DefaultDomains...)
	}
	if len(o.LeafnodeDomains) == 0 {
		o.LeafnodeDomains = append(o.LeafnodeDomains, o.DefaultDomains...)
	}
	if o.LetsEncryptCA == "" {
		o.LetsEncryptCA = certmagic.LetsEncryptProductionCA
	}
	if o.LoggingPreset != "production" {
		o.LoggingPreset = "development"
	}
	if o.LetsEncryptDataDir == "" {
		o.LetsEncryptDataDir = defaultDataDir()
	}
	if o.NatsExporterConfig != nil {
		if o.NatsExporterConfig.Host == "" {
			o.NatsExporterConfig.Host = "0.0.0.0"
		}
		if o.NatsExporterConfig.Features == nil {
			o.NatsExporterConfig.Features = &NatsExporterFeatures{
				Varz:          true,
				Connz:         true,
				ConnzDetailed: true,
				Subz:          true,
				Routez:        true,
				Healthz:       true,
				Gatewayz:      true,
				Leafz:         true,
			}
		}
	}
	if o.LetsEncryptDnsChallengeTTL == 0 {
		o.LetsEncryptDnsChallengeTTL = 60
	}
	if o.LetsEncryptDnsPropagationTimeout == 0 {
		o.LetsEncryptDnsPropagationDelay = 60
	}
	return o
}

func (o *NatsMagic) Validate() error {
	if len(o.DefaultDomains) == 0 {
		return fmt.Errorf("at least one domain name is required using NATS_MAGIC_DOMAINS environment variable")
	}
	if o.LetsEncryptEmail == "" {
		return fmt.Errorf("letsencrypt email is required using NATS_MAGIC_EMAIL environment variable")
	}
	if o.LetsEncryptCA == "" {
		return fmt.Errorf("letsencrypt ca is required using NATS_MAGIC_CA environment variable")
	}
	return nil
}

func (o *NatsMagic) GetDomains() []string {
	allDomains := make(map[string]bool)
	addToSet(
		allDomains,
		o.DefaultDomains,
		o.StandardDomains,
		o.MonitoringDomains,
		o.WebsocketDomains,
		o.MQTTDomains,
		o.LeafnodeDomains,
	)
	return setToSlice(allDomains)
}

func (o *NatsMagic) GetDns01Solver() (*certmagic.DNS01Solver, error) {
	var provider certmagic.ACMEDNSProvider
	if o.LetsEncryptDnsProvider == DigitalOcean {
		dotoken := os.Getenv("DO_TOKEN")
		if dotoken == "" {
			dotokenfile := os.Getenv("DO_TOKEN_FILE")
			if dotokenfile == "" {
				return nil, fmt.Errorf("digitalocean token is required using either DO_TOKEN or DO_TOKEN_FILE environment variables")
			}
			token, err := os.ReadFile(dotokenfile)
			if err != nil {
				return nil, fmt.Errorf("failed to read digitalocean token file: %s", err.Error())
			}
			dotoken = string(token)
		}
		provider = &digitalocean.Provider{
			APIToken: dotoken,
		}
	} else if o.LetsEncryptDnsProvider == Azure {
		provider = &azure.Provider{
			TenantId:          os.Getenv("AZURE_TENANT_ID"),
			ClientId:          os.Getenv("AZURE_CLIENT_ID"),
			ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
			SubscriptionId:    os.Getenv("AZURE_SUBSCRIPTION_ID"),
			ResourceGroupName: os.Getenv("AZURE_RESOURCE_GROUP_NAME"),
		}
	} else if o.LetsEncryptDnsProvider == Route53 {
		provider = &route53.Provider{}
	} else {
		return nil, fmt.Errorf("dns01 provider %s not supported", o.LetsEncryptDnsProvider)
	}
	var propagationTimeout time.Duration
	if o.LetsEncryptDnsSkipPropagationCheck {
		propagationTimeout = -1
	} else {
		propagationTimeout = time.Second * time.Duration(o.LetsEncryptDnsPropagationTimeout)
	}
	return &certmagic.DNS01Solver{
		DNSProvider:        provider,
		TTL:                time.Second * time.Duration(o.LetsEncryptDnsChallengeTTL),
		PropagationDelay:   time.Second * time.Duration(o.LetsEncryptDnsPropagationDelay),
		PropagationTimeout: propagationTimeout,
		Resolvers:          o.LetsEncryptDnsResolvers,
	}, nil
}

func (o *NatsMagic) SetLogger() error {
	if o.LoggingPreset == "production" {
		if o.atom == nil {
			level := zap.NewAtomicLevelAt(zap.InfoLevel)
			o.atom = &level
		}
		config := zap.Config{
			Level:       *o.atom,
			Development: false,
			Sampling: &zap.SamplingConfig{
				Initial:    100,
				Thereafter: 100,
			},
			Encoding: "json",
			EncoderConfig: zapcore.EncoderConfig{
				TimeKey:        "ts",
				LevelKey:       "level",
				NameKey:        "logger",
				CallerKey:      "caller",
				FunctionKey:    zapcore.OmitKey,
				MessageKey:     "msg",
				StacktraceKey:  zapcore.OmitKey,
				LineEnding:     zapcore.DefaultLineEnding,
				EncodeLevel:    zapcore.LowercaseLevelEncoder,
				EncodeTime:     zapcore.EpochTimeEncoder,
				EncodeDuration: zapcore.SecondsDurationEncoder,
				EncodeCaller:   zapcore.ShortCallerEncoder,
			},
			OutputPaths:      []string{"stderr"},
			ErrorOutputPaths: []string{"stderr"},
		}
		logger, err := config.Build()
		if err != nil {
			return err
		}
		o.logger = logger.WithOptions(zap.AddStacktrace(zap.FatalLevel))
	} else {
		if o.atom == nil {
			level := zap.NewAtomicLevelAt(zap.DebugLevel)
			o.atom = &level
		}
		config := zap.Config{
			Level:       *o.atom,
			Development: true,
			Encoding:    "console",
			EncoderConfig: zapcore.EncoderConfig{
				// Keys can be anything except the empty string.
				TimeKey:        "T",
				LevelKey:       "L",
				NameKey:        "N",
				CallerKey:      "C",
				FunctionKey:    zapcore.OmitKey,
				MessageKey:     "M",
				StacktraceKey:  zapcore.OmitKey,
				LineEnding:     zapcore.DefaultLineEnding,
				EncodeLevel:    zapcore.CapitalLevelEncoder,
				EncodeTime:     zapcore.ISO8601TimeEncoder,
				EncodeDuration: zapcore.StringDurationEncoder,
				EncodeCaller:   zapcore.ShortCallerEncoder,
			},
			OutputPaths:      []string{"stderr"},
			ErrorOutputPaths: []string{"stderr"},
		}
		logger, err := config.Build()
		if err != nil {
			return err
		}
		o.logger = logger.WithOptions(zap.AddStacktrace(zap.FatalLevel))
	}
	return nil
}

func (o *NatsMagic) GetLogger(name string) *zap.Logger {
	if o.logger == nil {
		o.SetLogger()
	}
	if len(name) > 0 {
		return o.logger.Named(name)
	}
	return o.logger
}

func (o *NatsMagic) GetCertmagicConfig() (*certmagic.Config, error) {
	// Get DNS-01 solver
	solver, err := o.GetDns01Solver()
	if err != nil {
		return nil, fmt.Errorf("failed to create certmagic dns01 solver: %s", err.Error())
	}
	// Configure cert-magic
	certmagic.Default.Storage = &certmagic.FileStorage{Path: o.LetsEncryptDataDir}
	certmagic.Default.Logger = o.GetLogger("certmagic")
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = o.LetsEncryptCA
	certmagic.DefaultACME.Email = o.LetsEncryptEmail
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.DNS01Solver = solver
	// Configure cert-magic cache
	var cache *certmagic.Cache
	cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(cache, certmagic.Config{}), nil
		},
		Logger: o.GetLogger("certmagic"),
	})
	// Create new certmagic config
	magic := certmagic.New(cache, certmagic.Config{})
	// Obtain or renew TLS certificates for domainNames
	domainNames := o.GetDomains()
	err = magic.ManageSync(context.TODO(), domainNames)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain or renew TLS certificates: %s", err.Error())
	}
	return magic, nil
}

func (o *NatsMagic) UpdateNatsServerOptions(magic *certmagic.Config, serverOptions *server.Options) error {
	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
	serverOptions.LeafNode.TLSConfig = tlsConfig.Clone()
	serverOptions.Websocket.TLSConfig = tlsConfig.Clone()
	serverOptions.Websocket.NoTLS = false
	serverOptions.MQTT.TLSConfig = tlsConfig.Clone()
	serverOptions.TLSConfig = tlsConfig.Clone()
	serverOptions.TLS = true
	serverOptions.TLSVerify = false
	// Cluster TLS config
	// In order for a server to connect to a cluster, it must have a valid TLS cert
	// with a SAN that matches the route entry in the cluster configuration.
	certs, err := magic.ClientCredentials(context.TODO(), o.DefaultDomains)
	if err != nil {
		return err
	}
	// Cluster TLS configs
	serverOptions.Cluster.TLSConfig = tlsConfig.Clone()
	serverOptions.Cluster.TLSConfig.GetCertificate = nil
	serverOptions.Cluster.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	serverOptions.Cluster.TLSCheckKnownURLs = true
	serverOptions.Cluster.TLSMap = true
	serverOptions.Cluster.TLSConfig.Certificates = certs
	// Gateway TLS config
	serverOptions.Gateway.TLSConfig = tlsConfig.Clone()
	serverOptions.Gateway.TLSConfig.GetCertificate = nil
	serverOptions.Gateway.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	serverOptions.Gateway.TLSCheckKnownURLs = true
	serverOptions.Gateway.TLSMap = true
	serverOptions.Gateway.TLSConfig.Certificates = certs

	return nil
}

func (o *NatsMagic) SetupNatsServer(opts *server.Options) (*server.Server, error) {
	// Generate TLS config
	if o.Enabled() {
		if err := o.Validate(); err != nil {
			return nil, err
		}
		if opts.Debug || opts.Trace || opts.TraceVerbose {
			o.atom.SetLevel(zap.DebugLevel)
		}
		magic, err := o.GetCertmagicConfig()
		if err != nil {
			return nil, err
		}
		err = o.UpdateNatsServerOptions(magic, opts)
		if err != nil {
			return nil, err
		}
	}
	natsLogger := natslogger.New(o.GetLogger("nats"))
	// Create the server with appropriate options.
	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, err
	}
	ns.SetLoggerV2(natsLogger, opts.Debug, opts.Trace, opts.TraceVerbose)
	// Start things up. Block here until done.
	if err := server.Run(ns); err != nil {
		return nil, err
	}
	return ns, nil
}

func (o *NatsMagic) SetupNatsExporter(serverOpts *server.Options) *exporter.NATSExporter {
	// Get the default options, and set what you need to.  The listen address and port
	// is how prometheus can poll for collected data.
	exporterOpts := &exporter.NATSExporterOptions{
		NATSServerURL:    fmt.Sprintf("http://127.0.0.1:%d", serverOpts.HTTPPort),
		ListenAddress:    o.NatsExporterConfig.Host,
		ListenPort:       o.NatsExporterConfig.Port,
		ScrapePath:       exporter.DefaultScrapePath,
		RetryInterval:    time.Duration(exporter.DefaultRetryIntervalSecs) * time.Second,
		GetVarz:          o.NatsExporterConfig.Features.Varz,
		GetConnz:         o.NatsExporterConfig.Features.Connz,
		GetConnzDetailed: o.NatsExporterConfig.Features.ConnzDetailed,
		GetSubz:          o.NatsExporterConfig.Features.Subz,
		GetRoutez:        o.NatsExporterConfig.Features.Routez,
		GetHealthz:       o.NatsExporterConfig.Features.Healthz,
		GetGatewayz:      o.NatsExporterConfig.Features.Gatewayz,
		GetLeafz:         o.NatsExporterConfig.Features.Leafz,
	}
	// create an exporter instance, ready to be launched.
	exp := exporter.NewExporter(exporterOpts)
	collector.RemoveLogger()
	expLogger := natslogger.New(o.GetLogger("exporter"))
	collector.SetLogger(expLogger)
	return exp
}

// Update embedded NATS server configuration to include credentials
// for leafnode remote accounts.
// If no remote leafnode are configured,  or no remote users are provided
// in the configuration, this function does nothing.
func (o *NatsMagic) unsafeUpdateNatsConfig() error {
	if o.NatsConfig["leafnodes"] == nil {
		return nil
	}
	leafnodes := o.NatsConfig["leafnodes"].(map[string]interface{})
	if _, ok := leafnodes["remotes"]; !ok {
		return nil
	}
	remotes := leafnodes["remotes"].([]interface{})
	if len(remotes) == 0 {
		return nil
	}
	if o.remoteUserCreds == nil {
		o.remoteUserCreds = make(map[string]string)
	}
	for _, l := range remotes {
		config := l.(map[string]interface{})
		if acc, ok := config["account"]; ok {
			if acc == nil {
				continue
			}
			account := acc.(string)
			creds, ok := o.remoteUserCreds[account]
			if !ok {
				user, ok := o.RemoteUsers[account]
				if ok {
					creds = writeRemoteUserCreds(account, user)
					o.remoteUserCreds[account] = creds
					config["credentials"] = creds
				} else {
					continue
				}
			} else {
				config["credentials"] = creds
			}
		}
	}
	return nil
}

// Set environment variables for DNS01 challenge
// This function does not validate the environment variables
// nor does it know which environment variables to expect.
// It simply sets the environment variables after transforming names to uppercase
// to given value (as-is).
func (o *NatsMagic) unsafeUpdateDnsAuth() error {
	for key, value := range o.LetsEncryptDnsAuth {
		err := os.Setenv(strings.ToUpper(key), value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Clean-up files created by natsmagic
// This function is always called on shutdown.
func (o *NatsMagic) Cleanup() {
	logger := o.GetLogger("cleanup").Sugar()
	if o.remoteUserCreds != nil {
		for _, creds := range o.remoteUserCreds {
			err := os.Remove(creds)
			if err != nil {
				logger.Errorf("failed to remove remote user creds: %s", err)
			}
		}
	}
}

func readNatsMagicFromFile(filepath string, magicOpts *NatsMagic) error {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, &magicOpts)
	if err != nil {
		return err
	}
	return nil
}

func readNatsMagicFromUrl(url string, magicOpts *NatsMagic) error {
	repo := magicrepo.NewHttpMagicRepo(url, os.Getenv("NATS_MAGIC_SERVER"))
	content, err := repo.GetRawMagic()
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, &magicOpts)
	if err != nil {
		return err
	}
	return nil
}

type DnsProvider int

const (
	DigitalOcean DnsProvider = iota // Route53 = 0
	Azure                           // Route53 = 1
	Route53                         // Route53 = 2
)

func (p DnsProvider) String() string {
	return []string{"digitalocean", "azure", "route53"}[p]
}

func (p DnsProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *DnsProvider) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	newp := NewDnsProviderFromString(s)
	*p = newp
	return nil
}

func NewDnsProviderFromString(s string) DnsProvider {
	switch s {
	case "digitalocean":
		return DigitalOcean
	case "azure":
		return Azure
	case "route53":
		return Route53
	}
	return DigitalOcean
}

type RemoteUser struct {
	Nkey  string `json:"nkey"`
	Token string `json:"token"`
}

func addToSet(set map[string]bool, slices ...[]string) {
	for _, items := range slices {
		for _, item := range items {
			if item == "" {
				continue
			}
			set[item] = true
		}
	}
}

func setToSlice(set map[string]bool) []string {
	slice := []string{}
	for k := range set {
		if len(k) > 0 {
			slice = append(slice, k)
		}
	}
	return slice
}

func getCommaSeparateEnv(env string) []string {
	value := os.Getenv(env)
	if value == "" {
		return []string{}
	}
	splitted := strings.Split(value, ",")
	cleaned := make([]string, len(splitted))
	for i, v := range splitted {
		trimmed := strings.TrimSpace(v)
		cleaned[i] = trimmed
	}
	return cleaned
}

func getIntegerEnv(env string) int {
	value := os.Getenv(env)
	if value == "" {
		return 0
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return intValue
}

func getBoolEnv(env string) bool {
	value := os.Getenv(env)
	if value == "" {
		return false
	}
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return boolValue
}

func writeRemoteUserCreds(system_account_key string, user *RemoteUser) string {
	dirpath, err := os.MkdirTemp("", "natsmagic")
	if err != nil {
		panic(err)
	}
	filepath := path.Join(dirpath, fmt.Sprintf("%s.creds", system_account_key))
	file, err := os.Create(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = os.Chmod(filepath, 0600)
	if err != nil {
		panic(err)
	}
	tmpl, err := template.New("creds").Parse(`-----BEGIN NATS USER JWT-----
{{.Token}}
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
{{.Nkey}}
------END USER NKEY SEED------

*************************************************************
`)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(file, user)
	if err != nil {
		panic(err)
	}
	return filepath
}

func defaultDataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "certmagic")
}

// homeDir returns the best guess of the current user's home
// directory from environment variables. If unknown, "." (the
// current directory) is returned instead.
func homeDir() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" {
		home = "."
	}
	return home
}
