.PHONY: setup test lint run-api run-ui compose-up compose-down

setup:
	python -m venv .venv
	.venv/bin/pip install -e "backend[dev]"
	cd frontend && npm ci

test:
	cd backend && pytest

lint:
	cd backend && ruff check app tests
	cd frontend && npm run lint

run-api:
	cd backend && uvicorn app.main:app --reload --port 8000

run-ui:
	cd frontend && npm run dev

compose-up:
	docker compose up --build

compose-down:
	docker compose down

