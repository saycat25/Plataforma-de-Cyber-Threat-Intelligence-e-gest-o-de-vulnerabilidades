.PHONY: test lint format run migrate

test:
	cd backend && pytest -q

lint:
	cd backend && ruff check app tests

format:
	cd backend && ruff format app tests

run:
	cd backend && uvicorn app.main:app --reload

migrate:
	cd backend && alembic upgrade head
