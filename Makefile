.PHONY: upload
upload:
	vagrant upload manage.sh
	vagrant upload main.go

.PHONY: run
run:
	go run main.go run ps -ax
