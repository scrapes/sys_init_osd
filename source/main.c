#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ppu-lv2.h>

#include <sys/memory.h>
#include <sys/process.h>
#include <sys/systime.h>
#include <sys/thread.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <lv2/sysfs.h>

#define FS_S_IFMT 0170000
#define LOG_LVL 0

#define PAYLOAD_PATH		"/dev_hdd0/SNMAPI/payloads/payload_%X.bin"
#define PRX_PATH			"/dev_hdd0/SNMAPI/sys_proc.sprx"
#define CONF_PATH			"/dev_hdd0/SNMAPI/modules.list"

#define SYSCALL_NOT_IMPL		0x3C60800160630003ULL
#define SYSCALL_NOT_IMPL2		0x4E800020
#define LV2_BEGIN_SEEK			0x8000000000000000ULL
#define LV2_END_SEEK			0x8000000000600000ULL

#define rand_int32_TT800		rand

#define PRX_SYSCALL			1022
#define PRX_SYSCALL_OFFSET	0x80000000007F0000ULL
#define PRX_SYSCALL_LOAD	0x1EE7
#define PRX_SYSCALL_UNLOAD	0x364F


int dev_rw_mounted = 0;
sysFSStat stat1;
int verbose = 0;
int from_reboot = 0;

char* anton = "Scrapes n Maze are L33t";


int console_write(const char * s)
{ 
	u32 len;
	lv2syscall4(403, 0, (u64) s, strlen(s), (u64) &len);
	return_to_user_prog(int);
}

u64 lv2peek(u64 addr) 
{ 
    lv2syscall1(6, (u64) addr);
    return_to_user_prog(u64);

}

u64 lv2poke(u64 addr, u64 value) 
{ 
    lv2syscall2(7, (u64) addr, (u64) value); 
    return_to_user_prog(u64);
}

u32 lv2peek32(u64 addr) {
    u32 ret = (u32) (lv2peek(addr) >> 32ULL);
    return ret;
}

u64 lv2poke32(u64 addr, u32 value) 
{ 
    return lv2poke(addr, (((u64) value) <<32) | (lv2peek(addr) & 0xffffffffULL));
}



u64 find_syscall()
{
	u64 i = LV2_END_SEEK;

	while(i>LV2_BEGIN_SEEK)
	{
		if(lv2peek(i) == SYSCALL_NOT_IMPL)
			if(((lv2peek(i+8) >> 32) & 0xFFFFFFFF) == SYSCALL_NOT_IMPL2)
				return i;
		i-=4;
	}
	return 0;
}

u64 reverse_search64(u64 val)
{
	u64 i = LV2_END_SEEK;

	while(i>LV2_BEGIN_SEEK)
	{
		if(lv2peek(i) == val)
			return i;
		i-=4;
	}
	return 0;
}

u64 search64(u64 val)
{
	u64 i;

	for(i=LV2_BEGIN_SEEK;i<LV2_END_SEEK;i+=4)
	{
		if(lv2peek(i) == val)
			return i;
	}
	return 0;
}

u64 find_syscall_table()
{
	u64 sc, opd_sc;

	sc = find_syscall();
	opd_sc = reverse_search64(sc);
	return search64(opd_sc);
}

int get_lv2_version()
{
	u64 toc = lv2peek(0x8000000000003000ULL);

	switch(toc)
	{
		case 0x8000000000366BD0ULL:
			return 0x446D;
		case 0x8000000000348DF0ULL:
			return 0x446C;
		case 0x800000000034B160ULL:
			return 0x450C;
		case 0x800000000036EC40ULL:
			return 0x450D;
		default:
			return 0;
	}
}

u64 get_syscall_table()
{
	int version = get_lv2_version();
	switch(version)
	{
		case 0x446C:
			return 0x800000000035E860ULL;
		case 0x446D:
			return 0x800000000037CFE8ULL;
		case 0x450C:
			return 0x800000000035F0D0ULL;
		case 0x450D:
			return 0x8000000000383658ULL;
	}

	return 0;
}


int install_syscall(int syscall_number, u64 *payload, u32 payload_size, u64 install_offset)
{
	u64 syscall_table = get_syscall_table();
	u64 payload_opd = install_offset + payload_size + 0x10;
	int i;
	
	if(syscall_table)
	{
		for(i=0;i<(payload_size/8);i++)
			lv2poke(install_offset+(i*8), payload[i]);

		lv2poke(payload_opd, install_offset);
		lv2poke(syscall_table + (8*syscall_number), payload_opd);
		// lv2poke(syscall_table + (8*1021), 0x8000000000324DF0ULL); //memcpy 4.46dex
		return 1;
	}

	return 0;
}

u64 find_vsh_process_obj()
{
	u64 vsh_str = reverse_search64(0x5F6D61696E5F7673ULL);
	return lv2peek((vsh_str + 0x70));
}


int lv2_memcpy(u64 target, u64 source, u32 size)
{
	lv2syscall3(1021, target, source, size);
	return_to_user_prog(u64);
}

void dump_lv2(char name[])
{
	//u8 buffer[0x1000];
	u64 i, val;

	FILE * out = fopen(name, "wb");

	for(i=0x8000000000000000;i<0x8000000000800000;i+=8)
	{
		val = lv2peek(i);
		fwrite(&val, 8, 1, out);
	}

	fclose(out);

}

void write_htab(void)
{
    u64 cont = 0;
    u64 reg5, reg6;
    u32 val;

    while(cont < 0x80) 
	{
        val = (cont << 7);

        reg5 = lv2peek(0x800000000f000000ULL | ((u64) val));
        reg6 = lv2peek(0x800000000f000008ULL | ((u64) val));
        reg6 = (reg6  & 0xff0000ULL) | 0x190ULL;

		lv2syscall8(10, 0, (cont << 3ULL), reg5, reg6, 0, 0, 0, 1);

        cont++;

    }
}

void lv2_patch_error(u64 lis_addr, u32 lis_instr, u64 ori_addr, u32 ori_instr)
{
	u64 val;
	val = (lv2peek(lis_addr) & 0xFFFFFFFF) | ((u64)lis_instr << 32);
	lv2poke(lis_addr, val);

	val = (lv2peek(ori_addr) & 0xFFFFFFFF) | ((u64)ori_instr << 32);
	lv2poke(ori_addr, val);
}

void print_hex(u8 * buf, u32 len)
{
	u32 i;
	for(i=0;i<len;i++)
	{
		printf("0x%02x,", buf[i]);
	}

	printf("\n");
}

void get_idps(u8 idps[])
{
	lv2syscall1(870, (u64)idps);
}

void get_psid(u8 psid[])
{
	lv2syscall1(872, (u64)psid);
}

void ring_buzzer()
{
	lv2syscall3(392, 0x1004, 0xa, 0x1b6);
}

u64 be64(u8 * buf)
{
	u64 val;
	memcpy(&val, buf, 8);
	return val;
}

u32 be32(u8 * buf)
{
	u32 val;
	memcpy(&val, buf, 4);
	return val;
}

void wbe64(u8 * buf, u64 val)
{
	memcpy(buf, &val, 8);
}

void wbe32(u8 * buf, u32 val)
{
	memcpy(buf, &val, 4);
}

void wbe16(u8 * buf, u16 val)
{
	memcpy(buf, &val, 2);
}

void wbe8(u8 * buf, u8 val)
{
	buf[0] = val;
}

void get_rand(u8 buf[], u32 len)
{
	int i;
	u32 tmp;

	srand((u32)time(NULL));

	for(i=0;i<len;i+=4)
	{
		tmp=rand_int32_TT800();
		memcpy(buf+i, &tmp, 4);
	}
}



u64 load_prx_module(u64 process_obj, u32 slot, char * path, void * arg, u32 arg_size)
{
    lv2syscall6(PRX_SYSCALL, PRX_SYSCALL_LOAD, (u64) process_obj, (u64) slot, (u64) path, (u64) arg, (u64) arg_size);
	return_to_user_prog(u64);
}

uint8_t * read_file(char *path, uint32_t * file_size, uint16_t round)
{
	uint8_t * buf;
	uint32_t size = 0;
	uint16_t rest;
	FILE * f = fopen(path, "rb");
	if(f)
	{
		uint32_t size = fseek(f, 0, SEEK_END);
		size = ftell(f);
		fseek(f, 0, SEEK_SET);

		if(round)
		{
			rest = size % round;
			if(rest)
				size = size - rest + round;
		}


		buf = malloc(size);
		fread(buf, size, 1, f);
		fclose(f);
		*(file_size) = size;
		return buf;
	}else{
		*(file_size) = 0;
		return NULL;
	}
}

int write_file(uint8_t * buf, char *path, uint32_t size)
{
	FILE * f = fopen(path, "wb");
	int result;
	if(f)
	{
		result = fwrite(buf, size, 1, f);
		fclose(f);
		return result;
	}else{
		return 0;
	}
}

u32 load_all_prx(char * config_path)
{
	char line[256];
	int len;
	u32 slot = 0;

	u64 result, vsh_process_obj;

	FILE * f = fopen(config_path,"r");

	if(!f)

		return 0;

	vsh_process_obj = find_vsh_process_obj();
	printf("vsh_process_obj found at: 0x%llx\n", vsh_process_obj);

	while(fgets(line, sizeof line, f) != NULL && slot < 6)
	{
		len = strlen(line);
		if(line[0] != '/' || len == 0)
			continue;

		if(line[len-1] == '\n')
			line[len-1] = 0;
		if(line[len-2] == '\r')
			line[len-2] = 0;

		result = load_prx_module(vsh_process_obj, slot, line, 0, 0);
		printf("load_prx_module %s returned: 0x%llx\n", line, result);
		slot++;
	}

	

	fclose(f);

	return slot;
}



extern int _sys_process_atexitspawn(u32 a, const char *file, u32 c, u32 d, u32 e, u32 f);

int launchself(const char*file)
{
	return _sys_process_atexitspawn(0, file, 0, 0, 0x3d9, 0x20);
    
}

int launchselfback(const char*file)
{
	return _sys_process_atexitspawn(0, file, 0, 0, 0x7d0, 0x20);
    
}

int sys_fs_mount_ext(char const* deviceName, char const* deviceFileSystem, char const* devicePath, int writeProt, u32* buffer, u32 count) 
{
    lv2syscall8(837, (u64) deviceName, (u64) deviceFileSystem, (u64) devicePath, 0ULL, (u64) writeProt, 0ULL, (u64) buffer, (u64) count);
    return_to_user_prog(int);
}

int sys_fs_umount(char const* devicePath) 
{
    lv2syscall3(838,  (u64) devicePath, 0, 0 );
    return_to_user_prog(int);
}

int filestat(const char *path, sysFSStat *stat)
{
    int ret = sysLv2FsStat(path, stat);

    if(ret == 0 && S_ISDIR(stat->st_mode)) return -1;
    
    return ret;
}

int unlink_secure(void *path)
{
    sysFSStat s;
    if(filestat(path, &s)>=0) {
        sysLv2FsChmod(path, FS_S_IFMT | 0777);
        return sysLv2FsUnlink(path);
    }
    return -1;
}

int sys_shutdown()
{   
    unlink_secure("/dev_hdd0/tmp/turnoff");
    
    lv2syscall4(379,0x1100,0,0,0);
    return_to_user_prog(int);
}

static int sys_reboot()
{
    unlink_secure("/dev_hdd0/tmp/turnoff");

    lv2syscall4(379,0x1200,0,0,0);
    return_to_user_prog(int);
}

int mount_flash()
{
    if(dev_rw_mounted || (!dev_rw_mounted && sys_fs_mount_ext("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_SnMapi", 0, NULL, 0)==0)) {

        dev_rw_mounted = 1;
    }

    return dev_rw_mounted;

}

char buffer[65536];

int file_copy(const char *src, const char *dst)
{
    sysFSStat stat1;
    int fd, fd2;
    int ret;
    u64 temp = 0;
    u64 readed = 0;

    if(filestat(src, &stat1)!=0 || stat1.st_size == 0) return -1;

    if(!sysLv2FsOpen(src, SYS_O_RDONLY, &fd, 0, NULL, 0)) {
        if(!sysLv2FsOpen(dst, SYS_O_WRONLY | SYS_O_CREAT | SYS_O_TRUNC, &fd2, 0777, NULL, 0)) {
            sysLv2FsChmod(dst, FS_S_IFMT | 0777);

            while(stat1.st_size != 0ULL) {
                readed = stat1.st_size;
                if(readed > 65536) readed = 65536;
                temp = 0;
                ret = sysLv2FsRead(fd, buffer, readed, &temp);
                if(ret < 0 || readed != temp) break;
                ret = sysLv2FsWrite(fd2, buffer, readed, &temp);
                if(ret < 0 || readed != temp) break;

                stat1.st_size -= readed;
            }

            sysLv2FsClose(fd);
            sysLv2FsClose(fd2);

            if(stat1.st_size) return -4;
        } else {
            sysLv2FsClose(fd);
            return -3;
        }
    } else return -2;

    return 0;
}

s32 main(s32 argc, const char* argv[]) 
{
	if(launchself("/dev_flash/sys/internal/sys_proc.self") != 0)
	{
		if(launchself("/dev_flash/vsh/module/vsh.self") != 0)
		{
		
		}
	}
	
	else
	{
		if(1 == 1)
		{
			sysSleep(5);
			sysFSStat s;
			if(filestat(CONF_PATH, &s)>=0) 
			{
				u64 * payload;
				u32 size;
				char payload_path[256];
				int lv2_version = get_lv2_version();

				if(!lv2_version)
				{
					ring_buzzer();
					printf("no suitable payload available\n");
					return -1;
				}
				write_htab();
				sprintf(payload_path, PAYLOAD_PATH, lv2_version);
				payload = (u64 *) read_file(payload_path, &size, 8);
				install_syscall(PRX_SYSCALL, payload, size, PRX_SYSCALL_OFFSET);
				free(payload);
				//patch permission 4.xx
				lv2poke(0x8000000000003D90ULL, 0x386000014E800020ULL); // usually "fixed" by warez payload
				printf("permission patch applied\n");
				load_all_prx(CONF_PATH);
			}
			
			else { printf("vsh module list not found!"); }
		}	
	}
	
	sysSleep(1);
	
	return 0;
}