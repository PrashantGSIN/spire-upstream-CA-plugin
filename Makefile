.PHONY: build clean test install

PLUGIN_NAME = spire-upstream-ca-plugin
BUILD_DIR = build
INSTALL_DIR = /opt/spire/plugins

build:
	@echo "Building $(PLUGIN_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(PLUGIN_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(PLUGIN_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

test:
	@echo "Running tests..."
	go test -v ./...

checksum: build
	@echo "Calculating SHA256 checksum..."
	@sha256sum $(BUILD_DIR)/$(PLUGIN_NAME) || shasum -a 256 $(BUILD_DIR)/$(PLUGIN_NAME)

install: build
	@echo "Installing plugin to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) $(INSTALL_DIR)/
	@chmod +x $(INSTALL_DIR)/$(PLUGIN_NAME)
	@echo "Plugin installed successfully"

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "Dependencies ready"

run-example:
	@echo "This target would run SPIRE server with the plugin"
	@echo "Configure your server.conf first, then run:"
	@echo "  spire-server run -config server.conf"
