/*
 * preseed_shim.c - inject Windows-derived pairing data into fprintd's
 * libfprint device before it opens the sensor.
 *
 * fprintd has no API to set libfprint persistent data, and the synatlsmoc
 * driver will send a fresh PAIR (invalidating Windows Hello) if none is set.
 * This shim interposes fp_context_enumerate() -- called once by fprintd at
 * startup -- and hooks FpContext::device-added so that every synatlsmoc
 * device receives the preseed before any open is attempted.
 *
 * It uses only the public libfprint API. The system libfprint/fprintd
 * binaries are left untouched; the systemd drop-in points fprintd at our
 * locally built libfprint and preloads this shim.
 *
 * Preseed file: /etc/fprint/8054-preseed.bin (root:root 0600).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <glib.h>
#include <libfprint/fprint.h>

#ifndef PRESEED_PATH
#define PRESEED_PATH "/etc/fprint/8054-preseed.bin"
#endif

static void
on_device_added (FpContext *ctx, FpDevice *dev, gpointer user_data)
{
  (void) ctx;
  (void) user_data;

  if (g_strcmp0 (fp_device_get_driver (dev), "synatlsmoc") != 0)
    return;

  g_autofree gchar *buf = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  if (!g_file_get_contents (PRESEED_PATH, &buf, &len, &error))
    {
      g_warning ("preseed-shim: cannot read %s: %s", PRESEED_PATH,
                 error ? error->message : "?");
      return;
    }

  /* API signature is non-const but does not modify the buffer. */
  if (!fp_device_set_persistent_data (dev, (guchar *) buf, len, &error))
    {
      g_warning ("preseed-shim: fp_device_set_persistent_data failed: %s",
                 error ? error->message : "?");
      return;
    }

  g_message ("preseed-shim: injected %zu bytes from %s into synatlsmoc device %s",
             len, PRESEED_PATH, fp_device_get_device_id (dev));
}

typedef void (*EnumerateFunc) (FpContext *ctx);

void
fp_context_enumerate (FpContext *ctx)
{
  static EnumerateFunc real_enumerate = NULL;
  static FpContext *hooked_ctx = NULL;

  if (!real_enumerate)
    {
      real_enumerate = (EnumerateFunc) dlsym (RTLD_NEXT, "fp_context_enumerate");
      if (!real_enumerate)
        {
          g_warning ("preseed-shim: dlsym(RTLD_NEXT, fp_context_enumerate) failed");
          return;
        }
    }

  if (hooked_ctx != ctx)
    {
      g_signal_connect (ctx, "device-added", G_CALLBACK (on_device_added), NULL);
      hooked_ctx = ctx;
      g_message ("preseed-shim: hooked FpContext::device-added (preseed %s)",
                 PRESEED_PATH);
    }

  real_enumerate (ctx);
}
