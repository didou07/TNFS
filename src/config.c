#include "config.h"
#include "platform.h"

static inline void safe_strncpy(char *dst, const char *src, size_t sz) {
    if (sz > 0) {
        size_t i;
        for (i = 0; i < sz - 1 && src[i]; i++) dst[i] = src[i];
        dst[i] = '\0';
    }
}

void conf_defaults(tnfs_conf_t *c) {
    memset(c, 0, sizeof(*c));
    safe_strncpy(c->host,      "127.0.0.1",   sizeof(c->host));
    c->port = 15050;
    safe_strncpy(c->user,      "tvcas",       sizeof(c->user));
    safe_strncpy(c->pass,      "1234",        sizeof(c->pass));
    safe_strncpy(c->deskey,    "0102030405060708091011121314", sizeof(c->deskey));
    safe_strncpy(c->caid,      "0B00",        sizeof(c->caid));
    safe_strncpy(c->sid,       "0001",        sizeof(c->sid));
    safe_strncpy(c->provid,    "000000",      sizeof(c->provid));
    safe_strncpy(c->masterkey, "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F",
            sizeof(c->masterkey));
    c->interval = 10;
    c->is_tvcas4 = 0;
}

void conf_load(tnfs_conf_t *c) {
    FILE *f = fopen(CONF_FILE, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char key[64], val[448];
        if (sscanf(line, " %63[^= ] = %447[^\r\n]", key, val) != 2) continue;
#define SET(field) safe_strncpy(c->field, val, sizeof(c->field))
        if      (!strcmp(key,"host"))      { SET(host); }
        else if (!strcmp(key,"port"))        c->port     = atoi(val);
        else if (!strcmp(key,"user"))      { SET(user); }
        else if (!strcmp(key,"pass"))      { SET(pass); }
        else if (!strcmp(key,"deskey"))    { SET(deskey); }
        else if (!strcmp(key,"caid"))      { SET(caid); }
        else if (!strcmp(key,"sid"))       { SET(sid); }
        else if (!strcmp(key,"provid"))    { SET(provid); }
        else if (!strcmp(key,"masterkey")) { SET(masterkey); }
        else if (!strcmp(key,"interval"))    c->interval = atoi(val);
        else if (!strcmp(key,"is_tvcas4"))  c->is_tvcas4 = atoi(val);
#undef SET
    }
    fclose(f);
}

void conf_save(const tnfs_conf_t *c) {
    FILE *f = fopen(CONF_FILE, "w");
    if (!f) return;
    fprintf(f, "host      = %s\n", c->host);
    fprintf(f, "port      = %d\n", c->port);
    fprintf(f, "user      = %s\n", c->user);
    fprintf(f, "pass      = %s\n", c->pass);
    fprintf(f, "deskey    = %s\n", c->deskey);
    fprintf(f, "caid      = %s\n", c->caid);
    fprintf(f, "sid       = %s\n", c->sid);
    fprintf(f, "provid    = %s\n", c->provid);
    fprintf(f, "masterkey = %s\n", c->masterkey);
    fprintf(f, "interval  = %d\n", c->interval);
    fprintf(f, "is_tvcas4 = %d\n", c->is_tvcas4);
    fclose(f);
}
