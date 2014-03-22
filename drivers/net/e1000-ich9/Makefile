###########################################################################
# Driver files
FAMILYC = e1000_82540.c e1000_82542.c e1000_82571.c e1000_82541.c \
	  e1000_82543.c e1000_ich8lan.c e1000_80003es2lan.c
FAMILYH = e1000_82571.h e1000_82541.h e1000_82543.h e1000_ich8lan.h \
	  e1000_80003es2lan.h

# core driver files
CFILES = e1000_main.c $(FAMILYC) e1000_mac.c e1000_nvm.c e1000_phy.c \
	 e1000_manage.c e1000_param.c e1000_ethtool.c kcompat.c e1000_api.c
HFILES = e1000.h e1000_hw.h e1000_osdep.h e1000_defines.h e1000_mac.h \
	 e1000_nvm.h e1000_manage.h $(FAMILYH) kcompat.h e1000_regs.h \
	 e1000_api.h

obj-m	+= e1000-ich9.o

e1000-ich9-objs := $(CFILES:.c=.o)
