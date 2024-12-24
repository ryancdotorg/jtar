OUTPUTS := $(strip $(wildcard jtar))
PYCACHE := $(strip $(wildcard src/__pycache__))

all: jtar

.PHONY: all install clean

jtar: src/*.py
ifneq ($(PYCACHE),)
	$(RM) $(PYCACHE)
endif
	python3 -m zipapp src -co jtar -p '/usr/bin/env python3' -m 'jtar:main'
	chmod +x jtar

install: jtar
	@cp -vu $< ~/bin/

clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_nop:
	@true
_clean:
ifneq ($(OUTPUTS),)
	$(RM) $(OUTPUTS)
endif
