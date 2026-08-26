package client_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aljojoby9/quietline/internal/client"
	qlcrypto "github.com/aljojoby9/quietline/internal/crypto"
	"github.com/aljojoby9/quietline/internal/server"
)

func startRelay(t *testing.T) (*httptest.Server, *server.Store) {
	t.Helper()
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ts := httptest.NewServer(server.New(store).Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

func TestRelayCannotDecrypt(t *testing.T) {
	ts, store := startRelay(t)
	ctx := context.Background()
	secret := "the-secret-is-waffles-42"

	alice, err := client.Register(ctx, t.TempDir(), ts.URL, "alice", "password1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := client.Register(ctx, t.TempDir(), ts.URL, "bob", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Send(ctx, "bob", secret); err != nil {
		t.Fatal(err)
	}

	envs, err := store.AllEnvelopes()
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) == 0 {
		t.Fatal("no envelopes stored")
	}
	for _, e := range envs {
		if bytes.Contains(e.Body, []byte(secret)) {
			t.Fatal("plaintext leaked into stored envelope body")
		}
		if bytes.Contains(e.Body, []byte("waffles")) {
			t.Fatal("plaintext fragment leaked into stored envelope body")
		}
		if len(e.Body) == 0 {
			t.Fatal("empty body")
		}
	}

	msgs, err := bob.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range msgs {
		if m.Kind == qlcrypto.KindText && m.Body == secret && m.From == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bob did not recover plaintext, got %#v", msgs)
	}

	// Offline follow-up: second message while bob is not listening.
	if err := alice.Send(ctx, "bob", "offline ping"); err != nil {
		t.Fatal(err)
	}
	msgs, err = bob.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, m := range msgs {
		if m.Body == "offline ping" {
			found = true
		}
	}
	if !found {
		t.Fatalf("offline sync missed message: %#v", msgs)
	}

	// Reply so both DH directions move.
	if err := bob.Send(ctx, "alice", "back at you"); err != nil {
		t.Fatal(err)
	}
	msgs, err = alice.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, m := range msgs {
		if m.Body == "back at you" {
			found = true
		}
	}
	if !found {
		t.Fatalf("alice missed reply: %#v", msgs)
	}

	n1, err := alice.Safety(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	n2, err := bob.Safety(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n2 {
		t.Fatalf("safety numbers differ:\n%s\n%s", n1, n2)
	}
	if !strings.Contains(n1, " ") {
		t.Fatalf("odd safety number: %q", n1)
	}
}

func TestWebsocketLiveDelivery(t *testing.T) {
	ts, _ := startRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alice, err := client.Register(ctx, t.TempDir(), ts.URL, "alice", "password1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := client.Register(ctx, t.TempDir(), ts.URL, "bob", "password1")
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- bob.Listen(ctx, func(m client.Message) {
			if m.Kind == qlcrypto.KindText {
				select {
				case got <- m.Body:
				default:
				}
			}
		})
	}()
	time.Sleep(200 * time.Millisecond)
	if err := alice.Send(ctx, "bob", "live wire"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m != "live wire" {
			t.Fatalf("got %q", m)
		}
	case err := <-errCh:
		t.Fatalf("listen ended: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for websocket delivery")
	}
}

func TestGroupSenderKeys(t *testing.T) {
	ts, store := startRelay(t)
	ctx := context.Background()

	alice, err := client.Register(ctx, t.TempDir(), ts.URL, "alice", "password1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := client.Register(ctx, t.TempDir(), ts.URL, "bob", "password1")
	if err != nil {
		t.Fatal(err)
	}
	carol, err := client.Register(ctx, t.TempDir(), ts.URL, "carol", "password1")
	if err != nil {
		t.Fatal(err)
	}

	g, err := alice.CreateGroup(ctx, "room", []string{"bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SendGroup(ctx, g.ID, "hello group"); err != nil {
		t.Fatal(err)
	}

	envs, err := store.AllEnvelopes()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		if bytes.Contains(e.Body, []byte("hello group")) {
			t.Fatal("group plaintext leaked into store")
		}
	}

	want := false
	for _, user := range []*client.Client{bob, carol} {
		msgs, err := user.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, m := range msgs {
			if m.Kind == qlcrypto.KindGroup && m.Body == "hello group" && m.From == "alice" {
				got = true
			}
		}
		if !got {
			t.Fatalf("%s missed group text: %#v", user.Username(), msgs)
		}
		want = true
	}
	if !want {
		t.Fatal("no members")
	}

	if err := bob.SendGroup(ctx, g.ID, "from bob"); err != nil {
		t.Fatal(err)
	}
	msgs, err := alice.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range msgs {
		if m.Kind == qlcrypto.KindGroup && m.Body == "from bob" {
			found = true
		}
	}
	if !found {
		t.Fatalf("alice missed bob group text: %#v", msgs)
	}
}
