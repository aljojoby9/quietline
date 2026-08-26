package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/aljojoby9/quietline/internal/client"
	qlcrypto "github.com/aljojoby9/quietline/internal/crypto"
)

func main() {
	fs := flag.NewFlagSet("ql", flag.ExitOnError)
	home := fs.String("home", client.DefaultHome(), "account directory (or QL_HOME)")
	server := fs.String("server", getenv("QL_SERVER", "http://127.0.0.1:8080"), "relay URL")
	fs.Usage = usage
	_ = fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *home, *server, args[0], args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ql: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, home, server, cmd string, args []string) error {
	switch cmd {
	case "register":
		if len(args) != 2 {
			return fmt.Errorf("usage: ql register <user> <password>")
		}
		c, err := client.Register(ctx, home, server, args[0], args[1])
		if err != nil {
			return err
		}
		fmt.Printf("registered %s  home=%s\n", c.Username(), c.Home())
		return nil
	case "login":
		if len(args) != 2 {
			return fmt.Errorf("usage: ql login <user> <password>")
		}
		c, err := client.Login(ctx, home, server, args[0], args[1])
		if err != nil {
			return err
		}
		fmt.Printf("logged in as %s\n", c.Username())
		return nil
	case "whoami":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		me, err := c.Me(ctx)
		if err != nil {
			fmt.Printf("%s  (offline: %v)\n", c.Username(), err)
			return nil
		}
		fmt.Printf("%s  otks=%d  spk=%d  server=%s\n", me.Username, me.OTKCount, me.SignedID, c.Server())
		return nil
	case "send":
		if len(args) < 2 {
			return fmt.Errorf("usage: ql send <user> <message...>")
		}
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		return c.Send(ctx, args[0], strings.Join(args[1:], " "))
	case "recv", "sync":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		msgs, err := c.Recv(ctx)
		if err != nil {
			return err
		}
		if len(msgs) == 0 {
			fmt.Println("(no messages)")
			return nil
		}
		for _, m := range msgs {
			printMsg(m)
		}
		return nil
	case "listen":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "listening as %s on %s\n", c.Username(), c.Server())
		return c.Listen(ctx, func(m client.Message) { printMsg(m) })
	case "safety":
		if len(args) != 1 {
			return fmt.Errorf("usage: ql safety <user>")
		}
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		n, err := c.Safety(ctx, args[0])
		if err != nil {
			return err
		}
		fmt.Println(n)
		return nil
	case "refill":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		return c.Refill(ctx)
	case "log":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, e := range c.Log() {
			peer := e.To
			if e.From != c.Username() {
				peer = e.From
			}
			if e.GroupID != "" {
				peer = e.GroupID[:min(8, len(e.GroupID))]
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Kind, peer, e.From, e.Body)
		}
		return w.Flush()
	case "group-create":
		if len(args) < 2 {
			return fmt.Errorf("usage: ql group-create <name> <member...>")
		}
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		g, err := c.CreateGroup(ctx, args[0], args[1:])
		if err != nil {
			return err
		}
		fmt.Printf("%s  %s  members=%s\n", g.ID, g.Name, strings.Join(g.Members, ","))
		return nil
	case "group-send":
		if len(args) < 2 {
			return fmt.Errorf("usage: ql group-send <id> <message...>")
		}
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		return c.SendGroup(ctx, args[0], strings.Join(args[1:], " "))
	case "groups":
		c, err := client.Load(home)
		if err != nil {
			return err
		}
		for id, g := range c.Groups() {
			fmt.Printf("%s  %s  members=%s\n", id, g.Name, strings.Join(g.Members, ","))
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func printMsg(m client.Message) {
	switch m.Kind {
	case qlcrypto.KindText:
		fmt.Printf("%s: %s\n", m.From, m.Body)
	case qlcrypto.KindGroup:
		gid := m.GroupID
		if len(gid) > 8 {
			gid = gid[:8]
		}
		fmt.Printf("%s[%s]: %s\n", m.From, gid, m.Body)
	case qlcrypto.KindSKDM:
		fmt.Printf("(sender key from %s, group %s)\n", m.From, m.GroupID)
	case qlcrypto.KindReceipt:
		fmt.Printf("(receipt %s %s)\n", m.From, m.Body)
	default:
		fmt.Printf("%s (%s): %s\n", m.From, m.Kind, m.Body)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func usage() {
	fmt.Fprintf(os.Stderr, `ql — quietline client

Usage:
  ql [--home DIR] [--server URL] <command>

Commands:
  register <user> <password>
  login <user> <password>
  whoami
  send <user> <message...>
  recv
  listen
  safety <user>
  refill
  log
  group-create <name> <member...>
  group-send <id> <message...>
  groups

Keys stay in --home (default QL_HOME or ~/.config/quietline).
`)
}
