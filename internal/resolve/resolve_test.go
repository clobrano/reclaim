package resolve

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fake(outputs map[string]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		if out, ok := outputs[key]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("not found")
	}
}

func TestRefresh(t *testing.T) {
	r := &Resolver{Timeout: time.Second, Run: fake(map[string]string{
		"podman ps --no-trunc --format json":       `[{"Id":"aaa","Names":["dev-control-plane"],"Labels":{"io.x-k8s.kind.cluster":"dev"}}]`,
		"docker ps --no-trunc --format {{json .}}": `{"ID":"bbb","Names":"redis","Labels":"a=b,c=d"}` + "\n",
		"kubectl config get-contexts -o name":      "kind-dev\nprod\n",
		"kubectl --context kind-dev get pods -A -o json": `{"items":[{"metadata":{"uid":"u1","name":"web-6d4b9-x2x","namespace":"default",
			"labels":{"pod-template-hash":"6d4b9"},"ownerReferences":[{"kind":"ReplicaSet","name":"web-6d4b9"}]}},
			{"metadata":{"uid":"u2","name":"kindnet-abc","namespace":"kube-system","ownerReferences":[{"kind":"DaemonSet","name":"kindnet"}]}}]}`,
	})}
	r.Refresh()
	name, labels, ok := r.Container("podman", "aaa")
	if !ok || name != "dev-control-plane" || labels["io.x-k8s.kind.cluster"] != "dev" {
		t.Fatal(name, labels, ok)
	}
	name, labels, _ = r.Container("docker", "bbb")
	if name != "redis" || labels["c"] != "d" {
		t.Fatal(name, labels)
	}
	p, ok := r.Pod("u1")
	if !ok || p.OwnerKind != "Deployment" || p.OwnerName != "web" || p.Context != "kind-dev" {
		t.Fatalf("%+v", p)
	}
	p, _ = r.Pod("u2")
	if p.OwnerKind != "DaemonSet" {
		t.Fatalf("%+v", p)
	}
	if _, ok := r.Pod("nope"); ok {
		t.Fatal("unknown pod")
	}
}

func TestRefreshNoTools(t *testing.T) {
	r := &Resolver{Timeout: time.Second, Run: fake(nil)}
	r.Refresh()
	if _, _, ok := r.Container("podman", "x"); ok {
		t.Fatal("expected nothing")
	}
}
