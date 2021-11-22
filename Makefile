all: jtar

.PHONY: all clean

jtar: src/*
	python3 -m zipapp src -co jtar -p '/usr/bin/env python3' -m 'jtar:main'

clean:
	rm -f jtar || /bin/true
