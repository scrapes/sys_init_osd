sys_init_osd
============

Source of sys_init_osd written by Estwald, modificated by scrapes and maze. Compiled with Estwalds PSDK3v2

This is not a replacement for the original sys_init_osd.self.
This new core loades the old one, besides it Activates and loads the VSH loader.

-We removed the load sm.self function due to crashes and unwanted processes.
-We removed every boot flag function, due to changes in core, system wont start and has to Reinstall again.
-We removed USB logging due to high failure and due to crashes of sys_init_osd_orig.self(sys_proc.self).
-We removed basically everything besides loadself, and some lv2 functions, but wrote our own Entry.
-/dev_rewrite/ is now /dev_SnMapi/


NOTE:
  This core isnt safe, no warranty. If you Brick(wich cant be happening), its not our fault.
  I highly recommend you, that you install PSDK3v2 and Compile the self by yourself, so its up to date,
  and you can modify it yourself.
  
  

