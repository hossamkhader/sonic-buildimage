# wpa package

WPASUPPLICANT_VERSION = 2.9.0-14

export WPASUPPLICANT_VERSION

WPASUPPLICANT = wpasupplicant_$(WPASUPPLICANT_VERSION)_$(CONFIGURED_ARCH).deb
$(WPASUPPLICANT)_SRC_PATH = $(SRC_PATH)/wpasupplicant
$(WPASUPPLICANT)_DEPENDS += $(LIBSWSSCOMMON_DEV) $(LIBNL3_DEV) $(LIBNL_GENL3_DEV) $(LIBNL_ROUTE3_DEV)
$(WPASUPPLICANT)_RDEPENDS += $(LIBSWSSCOMMON) $(LIBNL3) $(LIBNL_GENL3) $(LIBNL_ROUTE3)
SONIC_MAKE_DEBS += $(WPASUPPLICANT)

WPASUPPLICANT_DBG = wpasupplicant-dbgsym_$(WPASUPPLICANT_VERSION)_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(WPASUPPLICANT),$(WPASUPPLICANT_DBG)))

# hostapd is built from the same sonic-wpa-supplicant sources; PAC uses it as
# the 802.1X authenticator.
HOSTAPD = hostapd_$(WPASUPPLICANT_VERSION)_$(CONFIGURED_ARCH).deb
$(HOSTAPD)_RDEPENDS += $(LIBSWSSCOMMON) $(LIBNL3) $(LIBNL_GENL3) $(LIBNL_ROUTE3)
$(eval $(call add_derived_package,$(WPASUPPLICANT),$(HOSTAPD)))

HOSTAPD_DBG = hostapd-dbgsym_$(WPASUPPLICANT_VERSION)_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(WPASUPPLICANT),$(HOSTAPD_DBG)))

# The .c, .cpp, .h & .hpp files under src/{$DBG_SRC_ARCHIVE list}
# are archived into debug one image to facilitate debugging.
#
DBG_SRC_ARCHIVE += wpasupplicant
