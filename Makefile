
# Make file for procmon
CC=gcc
CFLAGS="-O"
TARGET := /usr/local/

procmon : procmon.c
	$(CC) $(CFLAGS) $< -o $@ 

all: 
	procmon
	install

# install as root
install: procmon
	cp -f procmon $(TARGET)bin
	if ! test -d $(TARGET)/man/man8; then
	    mkdir $(TARGET)/man/man8
	fi
	cp -f etc/procmon.8.gz $(TARGET)man/man8
	cp -f etc/procmon.init /etc/init.d
	cp -f etc/procmon.logrotate /etc/logrotate.d
	cp -f etc/30-procmon.conf /etc/rsyslog.d
	update-rc.d promon defaults
	service rsyslog restart
	service procmon start


clean:
	rm -r procmon
