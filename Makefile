CONFIG = build-config.json

ifneq ($(wildcard $(CONFIG)),)
REGISTRY   := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['registry'])")
IMAGE_NAME := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['image'])")
IMAGE_TAG  := $(shell python3 -c "import json;print(json.load(open('$(CONFIG)'))['target']['tag'])")
endif

IMAGE_REF = $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: configure build push clean create-secret

configure:
	bin/configure.py

build:
	docker build --platform=linux/amd64 -t $(IMAGE_REF) .

push: build
	docker push $(IMAGE_REF)

clean:
	-docker rmi $(IMAGE_REF)

create-secret:
	bin/create-secret.py $(SECRET_ARGS)
