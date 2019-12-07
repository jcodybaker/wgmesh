GO_VERSION := 1.13
KUBERNETES_VERSION := 1.16.3

image: dev
	docker build -t jcodybaker/wgmesh .

dev:
	docker build -t wgmesh-dev -f Dockerfile.dev \
		--build-arg=GO_VERSION=docker.io/golang:$(GO_VERSION) \
		--build-arg=KUBERNETES_GIT_TAG=kubernetes-$(KUBERNETES_VERSION) .

generate-k8s:
	docker run -v $$(pwd):/go/src/github.com/jcodybaker/wgmesh/ \
		wgmesh-dev:latest \
		/go/src/k8s.io/code-generator/generate-groups.sh \
		all \
		github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated \
		github.com/jcodybaker/wgmesh/pkg/apis \
		wgmesh:v1alpha1 \
		--go-header-file=hack/boilerplate.go.txt

image-push: 
	docker push jcodybaker/wgmesh

.PHONY: dev image
