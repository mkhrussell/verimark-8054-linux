/* Read-only device enumeration against the locally built libfprint. */
#include <glib.h>
#include <libfprint/fprint.h>

int
main (void)
{
  g_autoptr (FpContext) ctx = fp_context_new ();
  g_autoptr (GPtrArray) devices = fp_context_get_devices (ctx);

  g_print ("Found %u device(s)\n", devices->len);
  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *dev = g_ptr_array_index (devices, i);
      g_print ("[%u] driver=%s  id=%s  open=%s\n", i,
               fp_device_get_driver (dev), fp_device_get_device_id (dev),
               fp_device_is_open (dev) ? "yes" : "no");
    }
  return 0;
}
