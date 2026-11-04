package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSSHTCPProbeWithoutShellOrSFTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-probe-token" {
			t.Error("authorization header missing")
		}
		w.Write([]byte(`{"version":"v1.19.33"}`))
	}))
	defer upstream.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	var sessions atomic.Int32
	go func() {
		raw, e := listener.Accept()
		if e != nil {
			return
		}
		conn, channels, requests, e := ssh.NewServerConn(raw, cfg)
		if e != nil {
			raw.Close()
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		for ch := range channels {
			if ch.ChannelType() != "direct-tcpip" {
				sessions.Add(1)
				ch.Reject(ssh.UnknownChannelType, "disabled")
				continue
			}
			var target struct {
				Host       string
				Port       uint32
				Origin     string
				OriginPort uint32
			}
			if ssh.Unmarshal(ch.ExtraData(), &target) != nil || target.Host != "127.0.0.1" {
				ch.Reject(ssh.Prohibited, "invalid target")
				continue
			}
			socket, e := net.Dial("tcp", upstream.Listener.Addr().String())
			if e != nil {
				ch.Reject(ssh.ConnectionFailed, "unavailable")
				continue
			}
			channel, reqs, e := ch.Accept()
			if e != nil {
				socket.Close()
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				defer socket.Close()
				defer channel.Close()
				go io.Copy(channel, socket)
				io.Copy(socket, channel)
			}()
		}
	}()
	transport, e := DialSSH(context.Background(), SSHConfig{Address: listener.Addr().String(), User: "root", HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	httpTransport := &http.Transport{DialContext: transport.DialContext}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{Transport: httpTransport}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9090/version", nil)
	req.Header.Set("Authorization", "Bearer private-probe-token")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e != nil || string(b) != `{"version":"v1.19.33"}` {
		t.Fatal(string(b), e)
	}
	if sessions.Load() != 0 {
		t.Fatal("probe required shell/SFTP")
	}
}
