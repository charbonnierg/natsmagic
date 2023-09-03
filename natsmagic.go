package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/charbonnierg/natsmagic/magicopts"
	"github.com/nats-io/nats-server/v2/server"
	"go.uber.org/automaxprocs/maxprocs"
)

var EXE = "natsmagic"

var USAGE = `
Usage: natsmagic [options]

Example: start a server on port 4222 (tls) with monitoring on 8222 (https)

NATS_MAGIC_EMAIL=admin@example.com NATS_MAGIC_DOMAINS=nats.example.com natsmagic -p 4222 -ms 8222

Server Options:
    -a, --addr, --net <host>         Bind to host address (default: 0.0.0.0)
    -p, --port <port>                Use port for clients (default: 4222)
    -n, --name
        --server_name <server_name>  Server name (default: auto)
    -P, --pid <file>                 File to store PID
    -m, --http_port <port>           Use port for http monitoring
    -ms,--https_port <port>          Use port for https monitoring
    -c, --config <file>              Configuration file
    -t                               Test configuration and exit
    -sl,--signal <signal>[=<pid>]    Send signal to nats-server process (ldm, stop, quit, term, reopen, reload)
                                     pid> can be either a PID (e.g. 1) or the path to a PID file (e.g. /var/run/nats-server.pid)
        --client_advertise <string>  Client URL to advertise to other servers
        --ports_file_dir <dir>       Creates a ports file in the specified directory (<executable_name>_<pid>.ports).

Logging Options:
    -D, --debug                      Enable debugging output
    -V, --trace                      Trace the raw protocol
    -VV                              Verbose trace (traces system account as well)
    -DV                              Debug and trace
    -DVV                             Debug and verbose trace (traces system account as well)
        --max_traced_msg_len <len>   Maximum printable length for traced messages (default: unlimited)

JetStream Options:
    -js, --jetstream                 Enable JetStream functionality
    -sd, --store_dir <dir>           Set the storage directory

Authorization Options:
        --user <user>                User required for connections
        --pass <password>            Password required for connections
        --auth <token>               Authorization token required for connections

Cluster Options:
        --routes <rurl-1, rurl-2>    Routes to solicit and connect
        --cluster <cluster-url>      Cluster URL for solicited routes
        --cluster_name <string>      Cluster Name, if not set one will be dynamically generated
        --no_advertise <bool>        Do not advertise known cluster information to clients
        --cluster_advertise <string> Cluster URL to advertise to other servers
        --connect_retries <number>   For implicit routes, number of connect retries
        --cluster_listen <url>       Cluster url from which members can solicit routes

Profiling Options:
        --profile <port>             Profiling HTTP port

Common Options:
    -h, --help                       Show this message
    -v, --version                    Show version
        --help_tls                   TLS help

Magic Options (environment variables):
    NATS_MAGIC_DOMAINS               Default domain name for all servers (standard nats, websocket, mqtt, monitoring, leafnode)
    NATS_MAGIC_EMAIL                 Let's Encrypt account email address
    NATS_MAGIC_URL                   URL to fetch a natsmagic configuration file
    NATS_MAGIC_FILE                  Path to a natsmagic configuration file
    NATS_MAGIC_STANDARD_DOMAINS      Domain names for standard nats servers
    NATS_MAGIC_LEAFNODE_DOMAINS      Domain names for leafnode servers
    NATS_MAGIC_MONITORING_DOMAINS    Domain names for monitoring servers
    NATS_MAGIC_WEBSOCKET_DOMAINS     Domain names for websocket servers
    NATS_MAGIC_MQTT_DOMAINS          Domain names for mqtt servers
    NATS_MAGIC_CA                    Let's Encrypt CA (default to production CA: https://acme-v02.api.letsencrypt.org/directory)
    NATS_LOGGING_PRESET              Logging preset (default: development). Allowed values: [development, production]
`

func main() {
	magic, err := magicopts.New()
	defer magic.Cleanup()
	if err != nil {
		server.PrintAndDie(err.Error())
	}
	// Create a sugared logger for this entrypoint
	sugar := magic.GetLogger("natsmagic").Sugar()
	// Sync the logger on shutown
	defer sugar.Sync()
	// Create a FlagSet and sets the usage
	fs := flag.NewFlagSet(EXE, flag.ExitOnError)
	fs.Usage = usage
	// Save the args
	args := os.Args[1:]
	// Look for config-url environment
	if magic.NatsConfig != nil {
		config, err := json.Marshal(magic.NatsConfig)
		if err != nil {
			sugar.Fatalf("failed to marshal nats config: %s", err.Error())
		}
		filepath, err := writeConfigFile(config)
		sugar.Infof("saved config file to %s", filepath)
		if err != nil {
			sugar.Fatalf("failed to write configuration file: %s", err.Error())
		}
		args = append(args, "-c", filepath)
	}
	// Configure the options from the flags/config file
	serverOpts, err := server.ConfigureOptions(fs, args,
		server.PrintServerAndExit,
		fs.Usage,
		server.PrintTLSHelpAndDie)
	if err != nil {
		sugar.Fatalf("failed to configure server options: %s", err.Error())
	}
	if serverOpts.CheckConfig {
		fmt.Fprintf(os.Stderr, "%s: configuration file %s is valid\n", EXE, serverOpts.ConfigFile)
		os.Exit(0)
	}
	// Generate TLS config
	ns, err := magic.SetupNatsServer(serverOpts)
	if err != nil {
		sugar.Fatalf("failed to create nats server: %s", err.Error())
	}
	// Adjust MAXPROCS if running under linux/cgroups quotas.
	undo, err := maxprocs.Set(maxprocs.Logger(ns.Debugf))
	if err != nil {
		ns.Warnf("Failed to set GOMAXPROCS: %v", err)
	} else {
		defer undo()
	}
	// Wait for server shutdown
	ns.WaitForShutdown()
}

func usage() {
	fmt.Printf("%s\n", USAGE)
	os.Exit(0)
}

func writeConfigFile(content []byte) (string, error) {
	file, err := os.CreateTemp("", "nats-server")
	if err != nil {
		return "", err
	}
	defer file.Close()
	file.Write(content)
	return file.Name(), nil
}
