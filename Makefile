CONFIG = build-config.json

ifneq ($(wildcard $(CONFIG)),)
REGISTRY   := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['registry'])")
IMAGE_NAME := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['image'])")
IMAGE_TAG  := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['tag'])")
endif

IMAGE_REF = $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: init configure build push clean create-secret vault-setup

init:
	bin/agent-secretd-admin.py init $(INIT_ARGS)

configure:
	bin/agent-secretd-admin.py configure

build:
	docker build --platform=linux/amd64 -t $(IMAGE_REF) .

push: build
	docker push $(IMAGE_REF)

clean:
	-docker rmi $(IMAGE_REF)

create-secret:
	bin/agent-secretd-admin.py create-secret $(SECRET_ARGS)

vault-setup:
	bin/agent-secretd-admin.py vault-setup $(VAULT_ARGS)
