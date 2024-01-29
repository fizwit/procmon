# Makefile for procmon
CC=gcc
CFLAGS="-O"
TARGET := /usr/local

all: clean procmon

procmon : procmon.c
	${CC} ${CFLAGS} $< -o $@

# install as root
install: procmon
	cp -f procmon ${TARGET}/bin
	mkdir -p ${TARGET}/man/man8
	cp -f etc/procmon.8.gz ${TARGET}/man/man8
	cp -f etc/procmon.logrotate /etc/logrotate.d
	cp -f etc/30-procmon.conf /etc/rsyslog.d
	cp -f etc/procmon.service /etc/systemd/system
	systemctl daemon-reload
	systemctl enable procmon
	systemctl start procmon
	if systemctl list-unit-files --type=service | grep -q '^rsyslog.service'; then \
	  systemctl restart rsyslog; \
	else \
	  echo "rsyslog service not found, skipping rsyslog restart"; \
	fi
clean:
	rm -f procmon
