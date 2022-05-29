PYTHON=python3

pwn.state: pwn.orig.state craft.py pwn.gb
	$(PYTHON) craft.py

.PHONY: pwn.gb
pwn.gb:
	$(MAKE) -C ../rom pwn.gb
	ln -sf ../rom/pwn.gb pwn.gb

DOCKER=lima docker
CONTAINER_ID=3f515bf737b3
CONTAINER_PATH=/home/ctf/gearboy/platforms/linux/
TARGET_BINARY="$(CONTAINER_PATH)/gearboy.orig"

.PHONY: run
run: deploy
	$(DOCKER) exec -it "$(CONTAINER_ID)" bash -c "$(TARGET_BINARY) pwn.gb pwn.state; echo $$?"

.PHONY: run_debug
run_debug: deploy
	$(DOCKER) exec -it "$(CONTAINER_ID)" r2 -d "$(TARGET_BINARY)" pwn.gb pwn.state

.PHONY: deploy
deploy: pwn.state pwn.gb
	$(DOCKER) cp "$(shell pwd)/../rom/pwn.gb" "$(CONTAINER_ID):$(CONTAINER_PATH)/pwn.gb"
	$(DOCKER) cp "$(shell pwd)/pwn.state" "$(CONTAINER_ID):$(CONTAINER_PATH)/pwn.state"

LOCAL_BINARY=/Applications/Gearboy.app/Contents/MacOS/gearboy

.PHONY: run_local
run_local: pwn.gb
	$(LOCAL_BINARY) ./pwn.gb
