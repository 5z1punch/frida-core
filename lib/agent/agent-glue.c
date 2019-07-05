#include "frida-agent.h"

#include "frida-interfaces.h"
#include "frida-payload.h"

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
# include <signal.h>
#endif
#ifdef HAVE_GLIB_SCHANNEL_STATIC
# include <glib-schannel-static.h>
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
# include <glib-openssl-static.h>
#endif

#define MAX_LINE 512
#include <stdio.h>
#include <string.h>
#include <gum/guminterceptor.h>

int if_system_server (void)
{
  FILE *fp; 
  char strLine[MAX_LINE];
  char *s = "system_server";
  fp = fopen("/proc/self/cmdline", "r");
  fgets(strLine, MAX_LINE, fp);
  char *pos = strstr(strLine, s);
  fclose(fp);
  if(pos != NULL){
    return 1;
  }
  else{
    return 0;
  }  
}

void gum_agent_so_init (void)
{
      FILE *fp; 
      char strLine[MAX_LINE];
      char *s = "frida-agent-";
      fp = fopen("/proc/self/maps", "r");
      while (!feof(fp))
      { 
          fgets(strLine, MAX_LINE, fp);
          char *pos = strstr(strLine, s);
          if(pos != NULL){
            pos = strchr(strLine, ' ');
            if(*(pos+3) == 'x'){
              char so_start_hex[16];
              int addr_len = ((pos - strLine) - 1) / 2;
              so_start_hex[0] = '0';
              so_start_hex[1] = 'x';
              char so_end_hex[16];
              so_end_hex[0] = '0';
              so_end_hex[1] = 'x';
              strncpy(so_start_hex+2, strLine, addr_len);
              so_start_hex[addr_len+2] = '\0';
              strncpy(so_end_hex+2, strLine+addr_len+1, addr_len);
              so_end_hex[addr_len+2] = '\0';
              sscanf(so_start_hex, "%p", &agent_so_begin);
              sscanf(so_end_hex, "%p", &agent_so_end);
              break;
            }
          }
      } 
      fclose(fp);
}

void
_frida_agent_environment_init (void)
{
  gum_init_embedded ();
  frida_init_libc_shim ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_thread_garbage, NULL);

#ifdef HAVE_GLIB_SCHANNEL_STATIC
  g_io_module_schannel_register ();
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
  g_io_module_openssl_register ();
#endif

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
  /*
   * We might be holding the dynamic linker's lock, so force-initialize
   * our bsd_signal() wrapper on this thread.
   */
  bsd_signal (G_MAXINT32, SIG_DFL);
#endif
  if(if_system_server() != 1){
    gum_agent_so_init();
    agent_so_init_flag = 1;
  }
}

void
_frida_agent_environment_deinit (void)
{
  frida_deinit_libc_shim ();
  gum_deinit_embedded ();
}
