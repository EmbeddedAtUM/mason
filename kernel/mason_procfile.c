

#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>

#include "create_rsst.h"

#define PROCFS_NAME "mason_procfile"

static struct proc_dir_entry *Proc_File;

static int procfile_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	//struct property *pp = data;
	int n;

	if (off >= mason_log.length) {
		*eof = 1;
		return 0;
	}

	n = mason_log.length - off;
	if (n > count)
		n = count;
	else
		*eof = 1;

	memcpy(page, mason_log.buffer + off, n);
	*start = page;
	return n;
}

int init_module()
{
	/* create the /proc file */
	Proc_File = create_proc_entry(PROCFS_NAME, 0644, NULL);
			
	if (Proc_File == NULL) 
	{
		remove_proc_entry(PROCFS_NAME, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",PROCFS_NAME);
		return -ENOMEM;
	}

	Proc_File->read_proc  = procfile_read;
	Proc_File->write_proc = NULL;

	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);	
	return 0;	/* everything is ok */
}

void cleanup_module()
{
	remove_proc_entry(PROCFS_NAME, NULL);
	printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}
