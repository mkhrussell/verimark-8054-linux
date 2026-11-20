/*
 * Read-only probe for Synaptics Tudor Match-in-Sensor (047d:8054).
 *
 * Sends only VCSFW_CMD_GET_VERSION (0x01) on bulk OUT EP 0x01 and reads the
 * 38-byte response on bulk IN EP 0x81. This is the exact command the
 * synatlsmoc driver uses during open; it queries firmware metadata and does
 * NOT pair, enroll, reset, or modify fingerprint/pairing state.
 *
 * Build: gcc -o probe_version probe_version.c $(pkg-config --cflags --libs libusb-1.0)
 * Run:   ./probe_version
 */
#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <string.h>

#define VID 0x047d
#define PID 0x8054
#define EP_OUT 0x01
#define EP_IN 0x81
#define IFACE 0

static unsigned int
rd32le (const unsigned char *p)
{
  return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int) p[3] << 24);
}

static unsigned int
rd16le (const unsigned char *p)
{
  return p[0] | (p[1] << 8);
}

int
main (void)
{
  libusb_context *ctx = NULL;
  libusb_device_handle *dev = NULL;
  int rc;

  rc = libusb_init (&ctx);
  if (rc < 0)
    {
      fprintf (stderr, "libusb_init failed: %s\n", libusb_error_name (rc));
      return 1;
    }

  dev = libusb_open_device_with_vid_pid (ctx, VID, PID);
  if (!dev)
    {
      fprintf (stderr,
               "Could not open %04x:%04x (check permissions / udev rule)\n",
               VID, PID);
      libusb_exit (ctx);
      return 1;
    }
  printf ("Opened device %04x:%04x\n", VID, PID);

  rc = libusb_claim_interface (dev, IFACE);
  if (rc < 0)
    {
      fprintf (stderr, "claim_interface failed: %s\n", libusb_error_name (rc));
      libusb_close (dev);
      libusb_exit (ctx);
      return 1;
    }

  /* GET_VERSION: 1-byte command, no arguments. */
  const unsigned char cmd[1] = { 0x01 };
  int sent = 0;
  rc = libusb_bulk_transfer (dev, EP_OUT, (unsigned char *) cmd, sizeof (cmd),
                             &sent, 5000);
  if (rc < 0)
    {
      fprintf (stderr, "bulk OUT failed: %s\n", libusb_error_name (rc));
      goto out;
    }
  printf ("Sent GET_VERSION (%d byte)\n", sent);

  unsigned char buf[64];
  int got = 0;
  rc = libusb_bulk_transfer (dev, EP_IN, buf, sizeof (buf), &got, 5000);
  if (rc < 0)
    {
      fprintf (stderr, "bulk IN failed: %s\n", libusb_error_name (rc));
      goto out;
    }
  printf ("Received %d bytes\n", got);
  printf ("RAW: ");
  for (int i = 0; i < got; i++)
    printf ("%02x ", buf[i]);
  printf ("\n");

  if (got < 38)
    {
      fprintf (stderr, "Response too short (need 38: 2-byte status + 36 data)\n");
      goto out;
    }

  /* bytes[0..1] = status header; MisVersion starts at byte 2. */
  const unsigned char *v = buf + 2;
  printf ("status: 0x%02x 0x%02x\n", buf[0], buf[1]);
  printf ("build_time     : %u (0x%08x)\n", rd32le (v + 0), rd32le (v + 0));
  printf ("build_num      : %u (0x%08x)\n", rd32le (v + 4), rd32le (v + 4));
  printf ("version        : %u.%u\n", v[8], v[9]);
  printf ("target         : 0x%02x\n", v[10]);
  printf ("product_id     : 0x%02x ('%c')\n", v[11],
          v[11] >= 32 && v[11] < 127 ? v[11] : '?');
  printf ("silicon_rev    : 0x%02x\n", v[12]);
  printf ("formal_release : 0x%02x\n", v[13]);
  printf ("platform       : 0x%02x\n", v[14]);
  printf ("patch          : 0x%02x\n", v[15]);
  printf ("serial_number  : ");
  for (int i = 0; i < 6; i++)
    printf ("%02x", v[16 + i]);
  printf ("\n");
  printf ("security       : 0x%02x\n", v[22]);
  printf ("interface      : 0x%02x\n", v[23]);
  /* v[24..31] unknown8 */
  printf ("device_type    : 0x%04x\n", rd16le (v + 32));
  /* v[34] unknown1 */
  printf ("provision_state: %u (0x%02x)\n", v[35], v[35]);

out:
  libusb_release_interface (dev, IFACE);
  libusb_close (dev);
  libusb_exit (ctx);
  return 0;
}
