/*
 * Kernel Debugger Architecture Dependent Console I/O handler
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 1999-2006 Silicon Graphics, Inc.  All Rights Reserved.
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/delay.h>
#include <linux/console.h>
#include <linux/ctype.h>
#include <linux/keyboard.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>

#include <linux/kdb.h>
#include <linux/kdbprivate.h>
#include <pc_keyb.h>

#ifdef	CONFIG_VT_CONSOLE
#define KDB_BLINK_LED 1
#else
#undef	KDB_BLINK_LED
#endif

#ifdef	CONFIG_KDB_USB
struct kdb_usb_exchange kdb_usb_infos;

EXPORT_SYMBOL(kdb_usb_infos);

static unsigned char kdb_usb_keycode[256] = {
	  0,  0,  0,  0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38,
	 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,  2,  3,
	  4,  5,  6,  7,  8,  9, 10, 11, 28,  1, 14, 15, 57, 12, 13, 26,
	 27, 43, 84, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
	 65, 66, 67, 68, 87, 88, 99, 70,119,110,102,104,111,107,109,106,
	105,108,103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
	 72, 73, 82, 83, 86,127,116,117, 85, 89, 90, 91, 92, 93, 94, 95,
	120,121,122,123,134,138,130,132,128,129,131,137,133,135,136,113,
	115,114,  0,  0,  0,124,  0,181,182,183,184,185,186,187,188,189,
	190,191,192,193,194,195,196,197,198,  0,  0,  0,  0,  0,  0,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	 29, 42, 56,125, 97, 54,100,126,164,166,165,163,161,115,114,113,
	150,158,159,128,136,177,178,176,142,152,173,140
};

/* get_usb_char
 * This function drives the UHCI controller,
 * fetch the USB scancode and decode it
 */
static int get_usb_char(void)
{
	static int usb_lock;
	unsigned char keycode, spec;
	extern u_short plain_map[], shift_map[], ctrl_map[];

	/* Is USB initialized ? */
	if(!kdb_usb_infos.poll_func || !kdb_usb_infos.urb)
		return -1;

	/* Transfer char if they are present */
	(*kdb_usb_infos.poll_func)(kdb_usb_infos.uhci, (struct urb *)kdb_usb_infos.urb);

	spec = kdb_usb_infos.buffer[0];
	keycode = kdb_usb_infos.buffer[2];
	kdb_usb_infos.buffer[0] = (char)0;
	kdb_usb_infos.buffer[2] = (char)0;

	if(kdb_usb_infos.buffer[3])
		return -1;

	/* A normal key is pressed, decode it */
	if(keycode)
		keycode = kdb_usb_keycode[keycode];

	/* 2 Keys pressed at one time ? */
	if (spec && keycode) {
		switch(spec)
		{
			case 0x2:
			case 0x20: /* Shift */
				return shift_map[keycode];
			case 0x1:
			case 0x10: /* Ctrl */
				return ctrl_map[keycode];
			case 0x4:
			case 0x40: /* Alt */
				break;
		}
	}
	else {
		if(keycode) { /* If only one key pressed */
			switch(keycode)
			{
				case 0x1C: /* Enter */
					return 13;

				case 0x3A: /* Capslock */
					usb_lock ? (usb_lock = 0) : (usb_lock = 1);
					break;
				case 0x0E: /* Backspace */
					return 8;
				case 0x0F: /* TAB */
					return 9;
				case 0x77: /* Pause */
					break ;
				default:
					if(!usb_lock) {
						return plain_map[keycode];
					}
					else {
						return shift_map[keycode];
					}
			}
		}
	}
	return -1;
}
#endif	/* CONFIG_KDB_USB */

/*
 * This module contains code to read characters from the keyboard or a serial
 * port.
 *
 * It is used by the kernel debugger, and is polled, not interrupt driven.
 *
 */

#ifdef	KDB_BLINK_LED
/*
 * send:  Send a byte to the keyboard controller.  Used primarily to
 * 	  alter LED settings.
 */

static void
kdb_kbdsend(unsigned char byte)
{
	int timeout;
	for (timeout = 200 * 1000; timeout && (inb(KBD_STATUS_REG) & KBD_STAT_IBF); timeout--);
	outb(byte, KBD_DATA_REG);
	udelay(40);
	for (timeout = 200 * 1000; timeout && (~inb(KBD_STATUS_REG) & KBD_STAT_OBF); timeout--);
	inb(KBD_DATA_REG);
	udelay(40);
}

static void
kdb_toggleled(int led)
{
	static int leds;

	leds ^= led;

	kdb_kbdsend(KBD_CMD_SET_LEDS);
	kdb_kbdsend((unsigned char)leds);
}
#endif	/* KDB_BLINK_LED */

#if defined(CONFIG_SERIAL_8250_CONSOLE) || defined(CONFIG_SERIAL_CORE_CONSOLE)
#define CONFIG_SERIAL_CONSOLE
#endif

#if defined(CONFIG_SERIAL_CONSOLE)

struct kdb_serial kdb_serial;

static unsigned int
serial_inp(struct kdb_serial *kdb_serial, unsigned long offset)
{
	offset <<= kdb_serial->ioreg_shift;

	switch (kdb_serial->io_type) {
	case SERIAL_IO_MEM:
		return readb((void __iomem *)(kdb_serial->iobase + offset));
		break;
	default:
		return inb(kdb_serial->iobase + offset);
		break;
	}
}

/* Check if there is a byte ready at the serial port */
static int get_serial_char(void)
{
	unsigned char ch;

	if (kdb_serial.iobase == 0)
		return -1;

	if (serial_inp(&kdb_serial, UART_LSR) & UART_LSR_DR) {
		ch = serial_inp(&kdb_serial, UART_RX);
		if (ch == 0x7f)
			ch = 8;
		return ch;
	}
	return -1;
}
#endif /* CONFIG_SERIAL_CONSOLE */

#ifdef	CONFIG_VT_CONSOLE

static int kbd_exists;

/*
 * Check if the keyboard controller has a keypress for us.
 * Some parts (Enter Release, LED change) are still blocking polled here,
 * but hopefully they are all short.
 */
static int get_kbd_char(void)
{
	int scancode, scanstatus;
	static int shift_lock;	/* CAPS LOCK state (0-off, 1-on) */
	static int shift_key;	/* Shift next keypress */
	static int ctrl_key;
	u_short keychar;
	extern u_short plain_map[], shift_map[], ctrl_map[];

	if (KDB_FLAG(NO_I8042) || KDB_FLAG(NO_VT_CONSOLE) ||
	    (inb(KBD_STATUS_REG) == 0xff && inb(KBD_DATA_REG) == 0xff)) {
		kbd_exists = 0;
		return -1;
	}
	kbd_exists = 1;

	if ((inb(KBD_STATUS_REG) & KBD_STAT_OBF) == 0)
		return -1;

	/*
	 * Fetch the scancode
	 */
	scancode = inb(KBD_DATA_REG);
	scanstatus = inb(KBD_STATUS_REG);

	/*
	 * Ignore mouse events.
	 */
	if (scanstatus & KBD_STAT_MOUSE_OBF)
		return -1;

	/*
	 * Ignore release, trigger on make
	 * (except for shift keys, where we want to
	 *  keep the shift state so long as the key is
	 *  held down).
	 */

	if (((scancode&0x7f) == 0x2a) || ((scancode&0x7f) == 0x36)) {
		/*
		 * Next key may use shift table
		 */
		if ((scancode & 0x80) == 0) {
			shift_key=1;
		} else {
			shift_key=0;
		}
		return -1;
	}

	if ((scancode&0x7f) == 0x1d) {
		/*
		 * Left ctrl key
		 */
		if ((scancode & 0x80) == 0) {
			ctrl_key = 1;
		} else {
			ctrl_key = 0;
		}
		return -1;
	}

	if ((scancode & 0x80) != 0)
		return -1;

	scancode &= 0x7f;

	/*
	 * Translate scancode
	 */

	if (scancode == 0x3a) {
		/*
		 * Toggle caps lock
		 */
		shift_lock ^= 1;

#ifdef	KDB_BLINK_LED
		kdb_toggleled(0x4);
#endif
		return -1;
	}

	if (scancode == 0x0e) {
		/*
		 * Backspace
		 */
		return 8;
	}

	/* Special Key */
	switch (scancode) {
	case 0xF: /* Tab */
		return 9;
	case 0x53: /* Del */
		return 4;
	case 0x47: /* Home */
		return 1;
	case 0x4F: /* End */
		return 5;
	case 0x4B: /* Left */
		return 2;
	case 0x48: /* Up */
		return 16;
	case 0x50: /* Down */
		return 14;
	case 0x4D: /* Right */
		return 6;
	}

	if (scancode == 0xe0) {
		return -1;
	}

	/*
	 * For Japanese 86/106 keyboards
	 * 	See comment in drivers/char/pc_keyb.c.
	 * 	- Masahiro Adegawa
	 */
	if (scancode == 0x73) {
		scancode = 0x59;
	} else if (scancode == 0x7d) {
		scancode = 0x7c;
	}

	if (!shift_lock && !shift_key && !ctrl_key) {
		keychar = plain_map[scancode];
	} else if (shift_lock || shift_key) {
		keychar = shift_map[scancode];
	} else if (ctrl_key) {
		keychar = ctrl_map[scancode];
	} else {
		keychar = 0x0020;
		kdb_printf("Unknown state/scancode (%d)\n", scancode);
	}
	keychar &= 0x0fff;
	if (keychar == '\t')
		keychar = ' ';
	switch (KTYP(keychar)) {
	case KT_LETTER:
	case KT_LATIN:
		if (isprint(keychar))
			break;		/* printable characters */
		/* drop through */
	case KT_SPEC:
		if (keychar == K_ENTER)
			break;
		/* drop through */
	default:
		return(-1);	/* ignore unprintables */
	}

	if ((scancode & 0x7f) == 0x1c) {
		/*
		 * enter key.  All done.  Absorb the release scancode.
		 */
		while ((inb(KBD_STATUS_REG) & KBD_STAT_OBF) == 0)
			;

		/*
		 * Fetch the scancode
		 */
		scancode = inb(KBD_DATA_REG);
		scanstatus = inb(KBD_STATUS_REG);

		while (scanstatus & KBD_STAT_MOUSE_OBF) {
			scancode = inb(KBD_DATA_REG);
			scanstatus = inb(KBD_STATUS_REG);
		}

		if (scancode != 0x9c) {
			/*
			 * Wasn't an enter-release,  why not?
			 */
			kdb_printf("kdb: expected enter got 0x%x status 0x%x\n",
			       scancode, scanstatus);
		}

		kdb_printf("\n");
		return 13;
	}

	return keychar & 0xff;
}
#endif	/* CONFIG_VT_CONSOLE */

#ifdef	KDB_BLINK_LED

/* Leave numlock alone, setting it messes up laptop keyboards with the keypad
 * mapped over normal keys.
 */
static int kdba_blink_mask = 0x1 | 0x4;

#define BOGOMIPS (boot_cpu_data.loops_per_jiffy/(500000/HZ))
static int blink_led(void)
{
	static long delay;

	if (kbd_exists == 0)
		return -1;

	if (--delay < 0) {
		if (BOGOMIPS == 0)	/* early kdb */
			delay = 150000000/1000;     /* arbitrary bogomips */
		else
			delay = 150000000/BOGOMIPS; /* Roughly 1 second when polling */
		kdb_toggleled(kdba_blink_mask);
	}
	return -1;
}
#endif

get_char_func poll_funcs[] = {
#if defined(CONFIG_VT_CONSOLE)
	get_kbd_char,
#endif
#if defined(CONFIG_SERIAL_CONSOLE)
	get_serial_char,
#endif
#ifdef	KDB_BLINK_LED
	blink_led,
#endif
#ifdef	CONFIG_KDB_USB
	get_usb_char,
#endif
	NULL
};

/*
 * On some Compaq Deskpro's, there is a keyboard freeze many times after
 * exiting from the kdb. As kdb's keyboard handler is not interrupt-driven and
 * uses a polled interface, it makes more sense to disable motherboard keyboard
 * controller's OBF interrupts during kdb's polling.In case, of interrupts
 * remaining enabled during kdb's polling, it may cause un-necessary
 * interrupts being signalled during keypresses, which are also sometimes seen
 * as spurious interrupts after exiting from kdb. This hack to disable OBF
 * interrupts before entry to kdb and re-enabling them at kdb exit point also
 * solves the keyboard freeze issue. These functions are called from
 * kdb_local(), hence these are arch. specific setup and cleanup functions
 * executing only on the local processor - ashishk@sco.com
 */

void kdba_local_arch_setup(void)
{
#ifdef	CONFIG_VT_CONSOLE
	unsigned char c;

	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_command(KBD_CCMD_READ_MODE);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	while ( !(kbd_read_status() & KBD_STAT_OBF) );
	c = kbd_read_input();
	c &= ~KBD_MODE_KBD_INT;
	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_command(KBD_CCMD_WRITE_MODE);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_output(c);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	mdelay(1);
#endif	/* CONFIG_VT_CONSOLE */
}

void kdba_local_arch_cleanup(void)
{
#ifdef	CONFIG_VT_CONSOLE
	unsigned char c;

	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_command(KBD_CCMD_READ_MODE);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	while ( !(kbd_read_status() & KBD_STAT_OBF) );
	c = kbd_read_input();
	c |= KBD_MODE_KBD_INT;
	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_command(KBD_CCMD_WRITE_MODE);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	kbd_write_output(c);
	mdelay(1);
	while (kbd_read_status() & KBD_STAT_IBF);
	mdelay(1);
#endif	/* CONFIG_VT_CONSOLE */
}
