.PHONY: help build run shell test clean batch compare capture

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)CipherRun Docker Testing Environment$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""

build: ## Build Docker image
	@echo "$(BLUE)Building CipherRun Docker image...$(NC)"
	docker-compose build

run: ## Start container in background
	@echo "$(BLUE)Starting CipherRun container...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Container started!$(NC)"
	@echo "Run 'make shell' to enter the container"

shell: ## Enter the container shell
	@echo "$(BLUE)Entering CipherRun container...$(NC)"
	docker-compose exec cipherrun bash

stop: ## Stop the container
	@echo "$(BLUE)Stopping container...$(NC)"
	docker-compose down
	@echo "$(GREEN)Container stopped$(NC)"

# Testing targets
test: ## Run a quick test (google.com)
	@echo "$(BLUE)Testing google.com...$(NC)"
	docker-compose exec cipherrun cipherrun google.com

test-domain: ## Test specific domain (usage: make test-domain DOMAIN=example.com)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "$(RED)Error: Please specify DOMAIN$(NC)"; \
		echo "Usage: make test-domain DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "$(BLUE)Testing $(DOMAIN)...$(NC)"
	docker-compose exec cipherrun cipherrun $(DOMAIN)

batch: ## Run batch test on multiple domains
	@echo "$(BLUE)Running batch test...$(NC)"
	docker-compose exec cipherrun /scripts/batch-test.sh

compare: ## Compare ClientHello (usage: make compare DOMAIN=example.com)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "$(RED)Error: Please specify DOMAIN$(NC)"; \
		echo "Usage: make compare DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "$(BLUE)Comparing ClientHello for $(DOMAIN)...$(NC)"
	docker-compose exec cipherrun /scripts/compare-clienthello.sh $(DOMAIN)

capture: ## Capture and test (usage: make capture DOMAIN=example.com)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "$(RED)Error: Please specify DOMAIN$(NC)"; \
		echo "Usage: make capture DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "$(BLUE)Capturing traffic for $(DOMAIN)...$(NC)"
	docker-compose exec cipherrun /scripts/capture-and-test.sh $(DOMAIN)

# Analysis targets
results: ## Show latest results
	@echo "$(BLUE)Latest scan results:$(NC)"
	@ls -lth results/ | head -10

captures: ## Show captured PCAP files
	@echo "$(BLUE)Captured PCAP files:$(NC)"
	@ls -lth captures/ | head -10

analyze: ## Analyze latest PCAP with tshark
	@LATEST=$$(ls -t captures/*.pcap 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "$(RED)No PCAP files found$(NC)"; \
	else \
		echo "$(BLUE)Analyzing $$LATEST$(NC)"; \
		docker-compose exec cipherrun tshark -r $$LATEST; \
	fi

# Cleanup targets
clean-results: ## Clean results directory
	@echo "$(YELLOW)Cleaning results...$(NC)"
	rm -rf results/*
	@echo "$(GREEN)Results cleaned$(NC)"

clean-captures: ## Clean capture files
	@echo "$(YELLOW)Cleaning captures...$(NC)"
	rm -rf captures/*
	@echo "$(GREEN)Captures cleaned$(NC)"

clean: clean-results clean-captures ## Clean all generated files
	@echo "$(GREEN)All generated files cleaned$(NC)"

clean-all: clean ## Clean everything including Docker image
	@echo "$(YELLOW)Removing Docker image...$(NC)"
	docker-compose down -v
	docker rmi cipherrun:latest 2>/dev/null || true
	@echo "$(GREEN)Everything cleaned$(NC)"

# Development targets
rebuild: ## Rebuild Docker image from scratch
	@echo "$(BLUE)Rebuilding Docker image...$(NC)"
	docker-compose build --no-cache

logs: ## Show container logs
	docker-compose logs -f

ps: ## Show container status
	docker-compose ps

# Quick start guide
quickstart: build run ## Quick start: build and run
	@echo ""
	@echo "$(GREEN)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║           CipherRun Docker Environment Ready!                 ║$(NC)"
	@echo "$(GREEN)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Enter the container:   $(BLUE)make shell$(NC)"
	@echo "  2. Test a domain:         $(BLUE)make test-domain DOMAIN=google.com$(NC)"
	@echo "  3. Run batch test:        $(BLUE)make batch$(NC)"
	@echo "  4. Compare ClientHello:   $(BLUE)make compare DOMAIN=creand.es$(NC)"
	@echo "  5. Capture traffic:       $(BLUE)make capture DOMAIN=creand.es$(NC)"
	@echo ""
	@echo "$(YELLOW)View help:$(NC) make help"
	@echo ""

# Examples
examples: ## Show usage examples
	@echo "$(BLUE)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║                    Usage Examples                             ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(GREEN)Basic Testing:$(NC)"
	@echo "  make test-domain DOMAIN=google.com"
	@echo "  make test-domain DOMAIN=creand.es"
	@echo ""
	@echo "$(GREEN)Batch Testing:$(NC)"
	@echo "  make batch                    # Test 18 predefined domains"
	@echo "  make results                  # View results"
	@echo ""
	@echo "$(GREEN)Debugging TLS 1.3:$(NC)"
	@echo "  make compare DOMAIN=google.com    # Working domain"
	@echo "  make compare DOMAIN=creand.es     # Failing domain"
	@echo "  make captures                     # View PCAP files"
	@echo ""
	@echo "$(GREEN)Traffic Analysis:$(NC)"
	@echo "  make capture DOMAIN=creand.es     # Capture while testing"
	@echo "  make analyze                      # Analyze latest PCAP"
	@echo ""
	@echo "$(GREEN)Cleanup:$(NC)"
	@echo "  make clean                    # Clean results and captures"
	@echo "  make clean-all                # Clean everything including image"
	@echo ""
