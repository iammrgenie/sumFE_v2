CONTIKI_PROJECT = sumFE

all: $(CONTIKI_PROJECT)

PROJECT_SOURCEFILES += ecc.c test_ecc_utils.c

CONTIKI = /Users/mrgenie/contiki-ng

include $(CONTIKI)/Makefile.include


