default:
	docker compose up --force-recreate --build
detached:
	docker compose up -d --force-recreate --build
