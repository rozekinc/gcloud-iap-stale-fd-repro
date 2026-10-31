.PHONY: up down logs

# Starts A + B + UI idle. Start/stop, intensity and clearing results are in the UI.
up:
	mkdir -p results control
	rm -f control/intensity.json
	docker compose up -d --build
	@echo "UI: http://127.0.0.1:8099  (press Start there)"

# Removes the containers; results stay in results/.
down:
	docker compose down

logs:
	docker compose logs -f --tail=50
