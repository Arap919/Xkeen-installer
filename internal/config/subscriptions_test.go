package config

import (
	"context"
	"fmt"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/router"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubscriptionCountsAndHTTPS(t *testing.T) {
	for _, n := range []int{1, 10, 11} {
		urls := make([]string, n)
		for i := range urls {
			urls[i] = fmt.Sprintf("https://example.test/private/%d", i)
		}
		input, err := ResolveSubscriptions(context.Background(), urls, nil)
		if n == 11 {
			if err == nil {
				t.Fatal("accepted eleven subscriptions")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		p, err := Prepare(router.Snapshot{}, Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, input)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.File(MihomoPath)
		m, _ := mihomoDocument(b)
		if len(m["proxy-providers"].(map[string]any)) != n {
			t.Fatal("provider count")
		}
		if strings.Contains(p.String(), "private") {
			t.Fatal("URL leaked")
		}
	}
	if _, err := ResolveSubscriptions(context.Background(), []string{"http://example.test/secret"}, nil); err == nil {
		t.Fatal("accepted HTTP")
	}
}
func TestXraySubscriptionProxyOnly(t *testing.T) {
	b, err := mergeXraySubscriptions([][]byte{[]byte(`[{"dns":{"bad":true},"outbounds":[{"protocol":"freedom"},{"protocol":"vless","tag":"secret","settings":{"vnext":[{"address":"node.test","port":443,"users":[{"id":"test"}]}]}}]}]`)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "node.test") || strings.Contains(string(b), `"bad"`) || strings.Contains(string(b), "blocked-until-configured") {
		t.Fatal("base/import merge failed")
	}
	for _, raw := range []string{`{}`, `[]`, `{"outbounds":[{"protocol":"freedom"}]}`, `not json`} {
		if _, err := mergeXraySubscriptions([][]byte{[]byte(raw)}); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
}

func TestSubscriptionFetchAndFailures(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		want   bool
	}{
		{`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"node.test","port":443,"users":[{"id":"test"}]}]}}]}`, 200, true},
		{`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"node.test","port":443,"users":[{"id":"test"}]}]}}]}`, 500, false},
		{`not json`, 200, false},
		{strings.Repeat("x", MaxImportBytes+1), 200, false},
	} {
		client := &http.Client{Transport: subscriptionTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		input, err := resolveSubscriptions(context.Background(), client, Import{xrayURLs: []string{"https://example.test/private-token"}})
		if (err == nil) != tc.want {
			t.Fatalf("response acceptance mismatch: %v", err)
		}
		if err != nil {
			if strings.Contains(err.Error(), "private-token") {
				t.Fatal("secret leaked")
			}
			continue
		}
		p, err := Prepare(router.Snapshot{}, Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, input)
		if err != nil || !p.ActivationReady {
			t.Fatalf("proposal: %v %v", err, p)
		}
		if strings.Contains(p.String(), "private-token") {
			t.Fatal("proposal leaked")
		}
		sources, _ := p.File(XraySourcesPath)
		if !strings.Contains(string(sources), "private-token") {
			t.Fatal("sources missing")
		}
	}
}

type subscriptionTransport func(*http.Request) (*http.Response, error)

func (f subscriptionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdaterBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	files, err := ManagedSubscriptionFiles([]byte(`{"urls":["https://example.test/private-token"],"config_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	module := filepath.Join(dir, "update.py")
	if err = os.WriteFile(module, files[XrayUpdaterPath], 0600); err != nil {
		t.Fatal(err)
	}
	script := `import importlib.util,json,pathlib,sys,tempfile,unittest.mock as mock
spec=importlib.util.spec_from_file_location('updater',sys.argv[1]);u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
source=b'{"outbounds":[{"protocol":"vless","settings":{"id":"old"}}]}'
new=b'{"outbounds":[{"protocol":"vless","settings":{"id":"new"}}]}'
old=u.merge([source]); old_hash=u.hashlib.sha256(old).hexdigest(); assert u.owned(old,old_hash)
edited=json.loads(old);edited['dns']['queryStrategy']='UseIPv6';assert not u.owned(json.dumps(edited).encode(),old_hash)
edited=json.loads(old);edited['outbounds'][0]['settings']['id']='user';assert not u.owned(json.dumps(edited).encode(),old_hash)
edited=json.loads(old);edited['outbounds'].append(dict(edited['outbounds'][0],tag='subscription-node-2'));assert not u.owned(json.dumps(edited).encode(),old_hash)
try:u.merge([b'{"outbounds":[{"protocol":"vless","settings":{},"proxySettings":{"tag":"other"}}]}']);raise AssertionError()
except ValueError:pass
class Response:
 status=200
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def read(self,n):return new
class Opener:
 def open(self,*a,**kw):return Response()
with tempfile.TemporaryDirectory() as d:
 root=pathlib.Path(d);u.ROOT=root/'private';u.ROOT.mkdir();u.TARGET=root/'xray'/'configs'/'00-installer.json';u.TARGET.parent.mkdir(parents=True)
 (u.ROOT/'sources.json').write_text(json.dumps({'urls':['https://example.test/private-token'],'config_sha256':old_hash}));(u.ROOT/'sources.json').chmod(0o600)
 with mock.patch.object(u.urllib.request,'build_opener',return_value=Opener()),mock.patch.object(u,'xray_active',return_value=False):
  u.TARGET.write_bytes(old)
  with mock.patch.object(u,'run',return_value=False):
   try:u.update();raise AssertionError()
   except ValueError:pass
  assert u.TARGET.read_bytes()==old
  with mock.patch.object(u,'run',return_value=True) as run:
   u.update();assert len(run.call_args_list)==1
  assert json.loads(u.TARGET.read_bytes())==json.loads(u.merge([new]));assert u.TARGET.stat().st_mode&0o777==0o600
  assert json.loads((u.ROOT/'sources.json').read_bytes())['config_sha256']==u.hashlib.sha256(u.TARGET.read_bytes()).hexdigest()
  new=b'{"outbounds":[{"protocol":"vless","settings":{"id":"third"}}]}'
  with mock.patch.object(u,'run',return_value=True):u.update()
  assert json.loads(u.TARGET.read_bytes())==json.loads(u.merge([new]))
  assert json.loads((u.ROOT/'sources.json').read_bytes())['config_sha256']==u.hashlib.sha256(u.TARGET.read_bytes()).hexdigest()
 u.TARGET.write_bytes(old)
 (u.ROOT/'sources.json').write_text(json.dumps({'urls':['https://example.test/private-token'],'config_sha256':old_hash}))
 with mock.patch.object(u.urllib.request,'build_opener',return_value=Opener()),mock.patch.object(u,'xray_active',side_effect=[True,False]),mock.patch.object(u,'may_restart_xray',return_value=True,create=True),mock.patch.object(u,'run',side_effect=[True,False,True]) as run:
  try:u.update();raise AssertionError()
  except ValueError:pass
 assert u.TARGET.read_bytes()==old;assert len(run.call_args_list)==3
 assert json.loads((u.ROOT/'sources.json').read_bytes())['config_sha256']==old_hash
 for switch_phase in ('before_restart','before_recovery'):
  u.TARGET.write_bytes(old)
  source_file=u.ROOT/'sources.json'
  source_old=json.dumps({'urls':['https://example.test/private-token'],'config_sha256':old_hash}).encode()
  source_file.write_bytes(source_old)
  selected=['xray']
  real_atomic=u.atomic
  def atomic(path,data):
   real_atomic(path,data)
   if switch_phase=='before_restart' and path==source_file:selected[0]='mihomo'
  def run_command(command):
   if command[0]=='/opt/sbin/xray':return True
   assert selected[0]=='xray','restarted a switched core'
   selected[0]='mihomo'
   return False
  with mock.patch.object(u.urllib.request,'build_opener',return_value=Opener()),mock.patch.object(u,'xray_active',return_value=True),mock.patch.object(u,'may_restart_xray',side_effect=lambda:selected[0]=='xray',create=True),mock.patch.object(u,'atomic',side_effect=atomic),mock.patch.object(u,'run',side_effect=run_command) as run:
   if switch_phase=='before_restart':u.update()
   else:
    try:u.update();raise AssertionError('failed restart accepted')
    except ValueError:pass
  assert len(run.call_args_list)==(1 if switch_phase=='before_restart' else 2)
  if switch_phase=='before_restart':
   assert u.TARGET.read_bytes()==u.merge([new])
   assert json.loads(source_file.read_bytes())['config_sha256']==u.hashlib.sha256(u.TARGET.read_bytes()).hexdigest()
  else:
   assert u.TARGET.read_bytes()==old
   assert source_file.read_bytes()==source_old
with mock.patch.object(u.pathlib.Path,'read_bytes',return_value=b'name_client="xray"\n'),mock.patch.object(u.pathlib.Path,'glob',return_value=[]):
 assert u.may_restart_xray();assert not u.xray_active()
with mock.patch.object(u.pathlib.Path,'read_bytes',return_value=b'name_client="mihomo"\n'),mock.patch.object(u.pathlib.Path,'glob',return_value=[]):
 assert not u.may_restart_xray()
with mock.patch.object(u.pathlib.Path,'read_bytes',return_value=b'name_client="xray"\n'),mock.patch.object(u.pathlib.Path,'glob',return_value=[pathlib.Path('/proc/123/exe')]),mock.patch.object(u.os,'readlink',return_value='/opt/sbin/mihomo'):
 assert not u.may_restart_xray();assert not u.xray_active()
with mock.patch.object(u.pathlib.Path,'read_bytes',side_effect=FileNotFoundError):
 assert not u.may_restart_xray()

`
	cmd := exec.Command(python, "-c", script, module)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("updater checks: %v %s", err, out)
	}
}
