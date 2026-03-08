.PHONY: up down build logs clean stop gate dev test test-seq test-no-open test-report test-clean lint typecheck docs-check help run migrate-create migrate-up migrate-down migrate-history migrate-current prod-init prod-up prod-down prod-logs install-hooks

# Default target
help:
	@echo "AgentGate - AI Agent Middleware"
	@echo ""
	@echo "Usage:"
	@echo "  make up               Start all services (delegates to ./run demo)"
	@echo "  make down             Stop all services (delegates to ./run stop)"
	@echo "  make build            Rebuild containers"
	@echo "  make logs             View logs"
	@echo "  make clean            Full reset (delegates to ./run clean --wipe-data)"
	@echo "  make stop             Stop all services and preserve volumes"
	@echo "  make gate             Chronological quality gate (infra->lint->test)"
	@echo "  make dev              Start development servers (delegates to ./run dev)"
	@echo "  make test             Run tests (delegates to ./run test)"
	@echo "  make test-seq         Run tests (sequential)"
	@echo "  make test-no-open     Run tests without opening report"
	@echo "  make test-report      View Allure test report"
	@echo "  make test-clean       Clear all Allure results and history"
	@echo "  make lint             Run lint checks (delegates to ./run lint)"
	@echo "  make typecheck        Run mypy type checks (ea_agentgate package)"
	@echo "  make docs-check       Run strict docs governance checks"
	@echo "  make run              Interactive CLI (canonical entry: ./run)"
	@echo "  make install-hooks    Install git pre-commit hook (secret detection)"
	@echo ""
	@echo "Database Migrations:"
	@echo "  make migrate-create   Create new migration (MESSAGE='description')"
	@echo "  make migrate-up       Apply all pending migrations"
	@echo "  make migrate-down     Rollback last migration"
	@echo "  make migrate-history  View migration history"
	@echo "  make migrate-current  Show current migration version"
	@echo ""
	@echo "Production Deployment:"
	@echo "  make prod-init        Initialize production environment"
	@echo "  make prod-up          Start production services"
	@echo "  make prod-down        Stop production services"
	@echo "  make prod-logs        View production logs"
	@echo ""

# Docker commands
up:
	./run demo

down:
	./run stop

stop:
	./run stop

build:
	docker-compose build --no-cache

logs:
	./run logs

clean:
	./run clean --wipe-data

gate:
	./run gate

# Development (no Docker)
dev:
	./run dev

# Testing
test:
	./run test

test-seq:
	./run test --no-parallel

test-no-open:
	./run test --no-open

test-report:
	./run test --report

test-clean:
	./run test --clean

# Linting
lint:
	./run lint

# Type checking
typecheck:
	python3 -m mypy ea_agentgate

# Documentation governance checks
docs-check:
	./run docs-check

# Interactive CLI
run:
	./run $(filter-out $@,$(MAKECMDGOALS))

# Red-team LLM-assisted testing
redteam-llm:
	python3 -c "from server.mcp.ai_redteam import RedTeamGenerator; \
		g = RedTeamGenerator(); \
		r = g.generate_and_test(category='all', count=50); \
		print(r.model_dump_json(indent=2))"

# Install dependencies
install: install-hooks
	uv pip install -e ".[dev,server]"
	cd dashboard && npm install

# Install git hooks (secret detection pre-commit)
install-hooks:
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Installed pre-commit hook (secret detection)"

# Database migrations
migrate-create:
	@if [ -z "$(MESSAGE)" ]; then \
		echo "Error: MESSAGE is required. Usage: make migrate-create MESSAGE='your description'"; \
		exit 1; \
	fi
	alembic revision --autogenerate -m "$(MESSAGE)"

migrate-up:
	alembic upgrade head

migrate-down:
	alembic downgrade -1

migrate-history:
	alembic history --verbose

migrate-current:
	alembic current

# Production deployment
prod-init:
	./scripts/init_production.sh

prod-up:
	docker-compose -f docker-compose.production.yml up -d
	@echo ""
	@echo "AgentGate Production is running!"
	@echo "  Dashboard: http://localhost:3000"
	@echo "  API Docs:  http://localhost:3000/docs/api-reference"
	@echo "  Metrics:   http://localhost:9090/metrics"
	@echo ""

prod-down:
	docker-compose -f docker-compose.production.yml down

prod-logs:
	docker-compose -f docker-compose.production.yml logs -f
