# Wi-Fi Wanderer — build with plain swiftc (no SwiftPM needed).
#   make            build release binary ./wifi-wanderer
#   make debug      build with debug info
#   make install    copy to /usr/local/bin (PREFIX overridable)
#   make clean
NAME      := wifi-wanderer
SRC_DIR   := Sources/WiFiWanderer
SOURCES   := $(wildcard $(SRC_DIR)/*.swift)
PLIST     := $(SRC_DIR)/Info.plist
OUI_DB    := $(SRC_DIR)/Resources/manuf
PREFIX    ?= /usr/local
SWIFTC    ?= swiftc
SWIFTFLAGS ?= -O
LDFLAGS   := -framework CoreWLAN -framework CoreLocation \
             -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker $(PLIST) \
             -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __oui_db -Xlinker $(OUI_DB)

.PHONY: all debug install uninstall clean update-oui

all: $(NAME)

$(NAME): $(SOURCES) $(PLIST) $(OUI_DB)
	$(SWIFTC) $(SWIFTFLAGS) -swift-version 5 -module-name WiFiWanderer $(SOURCES) $(LDFLAGS) -o $@

debug: SWIFTFLAGS := -Onone -g
debug: $(NAME)

install: $(NAME)
	install -d $(PREFIX)/bin
	install -m 755 $(NAME) $(PREFIX)/bin/$(NAME)

uninstall:
	rm -f $(PREFIX)/bin/$(NAME)

update-oui:
	curl -fsSL https://www.wireshark.org/download/automated/data/manuf -o $(OUI_DB)

clean:
	rm -rf $(NAME) $(NAME).dSYM .build
