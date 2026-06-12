#ifndef CONFIG_H
#define CONFIG_H

#define CONF_FILE "tnfs.conf"

typedef struct {
    char host[256];
    int  port;
    char user[64];
    char pass[64];
    char deskey[64];
    char caid[16];
    char sid[16];
    char provid[16];
    char masterkey[128];
    int  interval;
} tnfs_conf_t;

void conf_defaults(tnfs_conf_t *c);
void conf_load(tnfs_conf_t *c);
void conf_save(const tnfs_conf_t *c);

#endif
