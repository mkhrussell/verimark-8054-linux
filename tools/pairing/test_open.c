/*
 * Validate synatlsmoc pairing/TLS using preseeded persistent data.
 *
 * This injects the Windows-derived pairing data via the public libfprint API,
 * then OPENs the device only. It does NOT enroll, delete, or pair.
 * Safe checkpoint: if the log shows "Need to pair sensor" the preseed failed;
 * if open completes, the TLS session was established with Windows' key.
 *
 * Build: gcc -o test_open test_open.c \
 *          -I<repo>/reference/libfprint-vojtapl \
 *          -I<repo>/reference/libfprint-vojtapl/libfprint \
 *          -I<repo>/build/libfprint \
 *          $(pkg-config --cflags glib-2.0 gio-unix-2.0 gusb) \
 *          -L<repo>/build/libfprint -lfprint-2 \
 *          $(pkg-config --libs glib-2.0 gio-unix-2.0 gusb) \
 *          -Wl,-rpath,<repo>/build/libfprint
 * Run:   G_MESSAGES_DEBUG=all ./test_open /path/to/preseed-file
 */
#include <glib.h>
#include <libfprint/fprint.h>
#include <stdio.h>
#include <stdlib.h>

static GMainLoop *loop;

static void
open_cb (FpDevice *dev, GAsyncResult *res, gpointer user_data)
{
  g_autoptr (GError) error = NULL;
  if (fp_device_open_finish (dev, res, &error))
    {
      g_print ("\n=== OPEN SUCCEEDED: TLS session established with preseeded key ===\n");
      /* process exit releases the device; no enroll/delete is performed */
    }
  else
    {
      g_printerr ("\n=== OPEN FAILED: %s ===\n", error ? error->message : "unknown");
    }
  g_main_loop_quit (loop);
}

int
main (int argc, char **argv)
{
  if (argc < 2)
    {
      fprintf (stderr, "usage: %s <preseed-file>\n", argv[0]);
      return 2;
    }

  g_autofree char *data = NULL;
  gsize len = 0;
  if (!g_file_get_contents (argv[1], &data, &len, NULL))
    {
      fprintf (stderr, "cannot read %s\n", argv[1]);
      return 1;
    }
  printf ("Loaded %zu bytes of preseed data from %s\n", len, argv[1]);

  g_autoptr (FpContext) ctx = fp_context_new ();
  g_autoptr (GPtrArray) devs = fp_context_get_devices (ctx);
  FpDevice *target = NULL;
  for (guint i = 0; i < devs->len; i++)
    {
      FpDevice *d = g_ptr_array_index (devs, i);
      if (g_strcmp0 (fp_device_get_driver (d), "synatlsmoc") == 0)
        {
          target = d;
          break;
        }
    }
  if (!target)
    {
      fprintf (stderr, "no synatlsmoc device found\n");
      return 1;
    }
  printf ("Device: driver=%s id=%s\n", fp_device_get_driver (target),
          fp_device_get_device_id (target));

  g_autoptr (GError) error = NULL;
  if (!fp_device_set_persistent_data (target, (guchar *) data, len, &error))
    {
      fprintf (stderr, "failed to set persistent data: %s\n",
               error ? error->message : "unknown");
      return 1;
    }
  printf ("Persistent data accepted by libfprint.\n");

  loop = g_main_loop_new (NULL, FALSE);
  fp_device_open (target, NULL, (GAsyncReadyCallback) open_cb, NULL);
  g_main_loop_run (loop);
  g_main_loop_unref (loop);
  return 0;
}
