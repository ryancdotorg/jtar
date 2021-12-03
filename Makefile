all: jtar

.PHONY: all install clean

jtar: src/*.py
	python3 -m zipapp src -co jtar -p '/usr/bin/env python3' -m 'jtar:main'

install: jtar
	@cp -vu $< ~/bin/

clean:
	rm -f jtar || /bin/true
