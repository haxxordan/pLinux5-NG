ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS := -std=c11 -Wall -Wextra -Werror -O2

fw1270_handoff_live.elf: fw1270_handoff_live.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f fw1270_handoff_live.elf
