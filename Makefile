CONTIKI_PROJECT = sumFE

all: $(CONTIKI_PROJECT)

PROJECT_SOURCEFILES += c25519.c ed25519.c f25519.c ecc.c

CONTIKI = /home/mrgenie/Projects/contiki-ng

include $(CONTIKI)/Makefile.include


