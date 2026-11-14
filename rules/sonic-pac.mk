# sonic-pac package: Port Access Control (802.1X authenticator / MAB)

SONIC_PAC_VERSION = 1.0.0
export SONIC_PAC_VERSION

SONIC_PAC = sonic-pac_$(SONIC_PAC_VERSION)_$(CONFIGURED_ARCH).deb
$(SONIC_PAC)_SRC_PATH = $(SRC_PATH)/sonic-pac
# MAB links against radius_lib built from the sonic-wpa-supplicant sources, so
# build after wpasupplicant to avoid two builds running in that tree at once.
$(SONIC_PAC)_DEPENDS += $(LIBSWSSCOMMON_DEV) $(LIBNL3_DEV) $(LIBNL_GENL3_DEV) $(LIBNL_ROUTE3_DEV) $(WPASUPPLICANT)
$(SONIC_PAC)_RDEPENDS += $(LIBSWSSCOMMON) $(LIBNL3) $(LIBNL_GENL3) $(LIBNL_ROUTE3) $(HOSTAPD)
SONIC_DPKG_DEBS += $(SONIC_PAC)

SONIC_PAC_DBG = sonic-pac-dbg_$(SONIC_PAC_VERSION)_$(CONFIGURED_ARCH).deb
$(SONIC_PAC_DBG)_DEPENDS += $(SONIC_PAC)
$(SONIC_PAC_DBG)_RDEPENDS += $(SONIC_PAC)
$(eval $(call add_derived_package,$(SONIC_PAC),$(SONIC_PAC_DBG)))

export SONIC_PAC SONIC_PAC_DBG
