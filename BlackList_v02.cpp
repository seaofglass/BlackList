////////////////////////////////////////////////////////////////////
//
// Black List (ver 0.2) published 05.23.2013
//
// programed by seaofglass@korea.com
//
//
////////////////////////////////////////////////////////////////////

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <lines.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <kernwin.hpp>
#include <hexrays.hpp>

 hexdsp_t *hexdsp = NULL;

 static bool inited = false;

int _msg(const char *format,...)
{
	va_list va;
	va_start(va, format);
	msg("BlackList:MSG# ");
	int nbytes = vmsg(format, va);
	va_end(va);
	return nbytes;
}

int _dmsg(const char *format,...)
{
	int nbytes = 0;
	if ( debug & IDA_DEBUG_PLUGIN )
	{
		va_list va;
		va_start(va, format);
		msg("BlackList:DBG# ");
		nbytes = callui(ui_msg, format, va).i;
		va_end(va);
	}
	return nbytes;
}

int init(void)
{
	const char *hxver = get_hexrays_version();

	if(strncmp(inf.procName, "metapc", 8) != 0)
	{
		_dmsg("Only support x86 architecture!!\n");
		return PLUGIN_SKIP;
	}

	if(inf.filetype != f_ELF && inf.filetype != f_PE)
	{
		_dmsg("It's a not PE or ELF format!!\n");
		return PLUGIN_SKIP;
	}

	
	if(!init_hexrays_plugin())
	{
		warning("Can't found Hex-rays!\n");
		return PLUGIN_SKIP;
	}
	
	msg("Black list plugin has been loaded (ver 0.2)!\n");
	msg("Hex-rays ver %s has been detected\n", hxver);

	inited = true;
	return PLUGIN_KEEP;
}

void term(void)
{
	if(inited)
	{
		_msg("now terminting hex-rays...\n");
		term_hexrays_plugin();
	}

	_msg("Black List was terminated.\nGood bye!\n\n");
	return;
}

//--------------------------------------------------------------------------
char *parameters[];

// column widths
static const int widths[] = { CHCOL_HEX|16, 24, 24, 24};

// column headers
static const char *header[] =
{
  "Address",
  "Function",
  "Parameter1",
  "Parameter2"
};

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static ulong idaapi sizer(void *obj)
{
  netnode *node = (netnode *)obj;
  return node->altval(-1);       }

//-------------------------------------------------------------------------
// function that generates the list line
static void idaapi desc(void *obj, ulong n, char * const *arrptr)
{
  // for the hexlay! 
  func_t *cfunc = NULL;
  func_t *pfn = get_func(get_screen_ea());
  hexrays_failure_t hf;

  if ( n == 0 ) 
  {
	// generate the column headers
    for ( int i=0; i < qnumber(header); i++ )
      qstrncpy(arrptr[i], header[i], MAXSTR);

    return;
  }
  netnode *node = (netnode *)obj;
  ea_t ea = node->altval(n-1);
  //ea_t parameters = node->altval(n-1);

  // 1st list item : Black List Function's Effective Address
  qsnprintf(arrptr[0], MAXSTR, "%08a", ea);

  // 2nd list item : function name.
  generate_disasm_line(ea, arrptr[1], MAXSTR, 0);
  tag_remove(arrptr[1], arrptr[1], MAXSTR);  // remove the color coding

  // 3rd list item : parameter1
  for(int find_push = 1; find_push < 15; find_push++)
  {
	generate_disasm_line(ea - find_push, arrptr[2], MAXSTR, 0);

	if(strstr(arrptr[2], "push"))
	{
		tag_remove(arrptr[2], arrptr[2], MAXSTR);  // remove the color coding
		break;
	}
  }

  // 4th list item : parameter2
  for(int find_push = 2 ; find_push < 30; find_push++)
  {
	generate_disasm_line(ea - find_push, arrptr[3], MAXSTR, 0);

	if(strstr(arrptr[3], "push") && !strstr(arrptr[3],"String1") && !strstr(arrptr[3], "Dest") || !strcmp(arrptr[3], arrptr[2]) || strstr(arrptr[3], "%%s"))
	{
		tag_remove(arrptr[3], arrptr[3], MAXSTR); 
		break;
	}
  }

  try
  {
	  cfunc_t *cfunc = decompile(pfn, &hf);

	  _msg("%a: successfully decompiled\n", pfn->startEA);
	  qstring bodytext;
      qstring_printer_t sp(cfunc, bodytext, false);
      cfunc->print_func(sp);

	  qsnprintf(arrptr[2], MAXSTR, "%s", bodytext.c_str()); 
  }
  catch (hexrays_failure_t &hf)
  {
	  _msg("warning!!\n");
	  return;
  }

  delete cfunc;
}

///////////////////////////////////////////////////////////////////////////
//
// function that is called when the user hits Enter
//
/////////////////////////////////////////////////////////////////////////

static void idaapi enter_cb(void *obj,ulong n)
{
  netnode *node = (netnode *)obj;
  jumpto(node->altval(n-1));
}

///////////////////////////////////////////////////////////////////////////
//
// function that is called when the window is closed
//
///////////////////////////////////////////////////////////////////////////

static void idaapi destroy_cb(void *obj)
{
  netnode *node = (netnode *)obj;
  node->kill();
  delete node;
}

void run(int /*arg*/)
{
	char title[] = "Black List";

	// Here's a X functions list! 
	char *black_list[] = {"strcpy", "_strcpy", "strcpyA", "strcpyW", "lstrcpy", "lstrcpyn", "lstrcpynA", "lstrcpyA", "lstrcpyW", 
						  "wcscpy", "mbscpy", "_mbscpy", "_tcscpy",
						  "sprintf", "_sprintf", "wsprintf", "wsprintfA", "wsprintfW", "swprintf", "_swprintf", "stprintf", "vsprintf", "vstprint", "vswprintf",
						  "scanf", "_scanf", "sscanf", "swscanf", "stscanf", "fscanf", "fwscanf", "ftscanf", "vscanf", "vsscanf", "vfscanf",
						  "strcat", "_strcat", "lstrcat", "lstrcatA", "strncat", "strcatbuff", "strcatbuffA", "strcatbuffW", "wcscat", "mbscat", "_mbscat",
						  "strFormatByteSize", "strFormatByteSizeA", "strFormatByteSizeW",
						  "strxfrm", "wcsxfrm", "_tcsxfrm",
						  "gets", "_gets", "fgets", "_fgets",
						  0};

	netnode *node = new netnode;
	node->create();

	int counter = 0;
	char *fun;

	// Works Message...
	show_wait_box("Black List ver 0.2\nNow Processing...\nWait!");
	
	clearBreak();

	int i =0;

		segment_t *seg = getnseg(i); 
		
			for(int i = 0; black_list[i] != 0; i++)
			{
				ea_t loc = BADADDR;
				loc = get_name_ea(seg->startEA, black_list[i]);

				fun = black_list[i];

				char info[MAXSTR]={0};
				char name[MAXSTR]={0};
				char cmt[MAXSTR]={0};
				char tmp[MAXSTR]={0};
				
				if(loc != BADADDR)
				{
					_msg("Finding callers to %15s (0x%a)\n", black_list[i], loc);

					xrefblk_t xb;
					
					bool ok = xb.first_to(loc, XREF_ALL);

					while(ok)
					{
						ea_t function_ea = xb.from;

						if(is_call_insn(function_ea))
						{
							node->altset(counter++, function_ea);
						}
						ok = xb.next_to();
					}
					node->altset(-1, counter); 
				} 	
			}	

			_msg("total : %d functions found...\n", counter);
			hide_wait_box();

			// now open the window
			choose2(false,                // non-modal window
					-1, -1, -1, -1,       // position is determined by Windows
					node,                 // pass the created netnode to the window
					qnumber(header),      // number of columns
					widths,               // widths of columns
					sizer,                // function that returns number of lines
					desc,                 // function that generates a line
					title,                // window title
					1,                    // use the default icon for the window
					0,                    // position the cursor on the first line
					NULL,                 // "kill" callback
					NULL,                 // "new" callback
					NULL,                 // "update" callback
					NULL,                 // "edit" callback
					enter_cb,             // function to call when the user pressed Enter
					destroy_cb,           // function to call when the window is closed
					NULL,                 // use default popup menu items
					NULL);                // use the same icon for all lines

	return;
}

//////////////////////////////////////////////////////////////////
//
// PLUGIN DESCRIPTION BLOCK
//
//////////////////////////////////////////////////////////////////

// public plugin name and version
char comment[] = "Black List version 0.2 by seaofglass";

// print where?
char help[] = "Find critical functions and show results at list box!\n";

// printed at plugin menu list
char name[] = "Black List v0.2";

// hotkey!
char hotkey[] = "Alt-7";


plugin_t PLUGIN =
{
		IDP_INTERFACE_VERSION,

		0,						// plugin flags

		init,					// initialize

		term,					// terminate. this pointer may be NULL.

		run,					// invoke plugin

		comment,				// long comment about the plugin.

		help,					// multiline help about the plugin

		name,					// the preffered short name of the plugin

		hotkey					// the preffered hotkey to run the plugin
};