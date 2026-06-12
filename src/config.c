#include "config.h"
#include "platform.h"

void conf_defaults(tnfs_conf_t *c) {
    memset(c, 0, sizeof(*c));
    strncpy(c->host,      "127.0.0.1",   sizeof(c->host)-1);
    c->port = 15050;
    strncpy(c->user,      "tvcas",       sizeof(c->user)-1);
    strncpy(c->pass,      "1234",        sizeof(c->pass)-1);
    strncpy(c->deskey,    "0102030405060708091011121314", sizeof(c->deskey)-1);
    strncpy(c->caid,      "0B00",        sizeof(c->caid)-1);
    strncpy(c->sid,       "0001",        sizeof(c->sid)-1);
    strncpy(c->provid,    "000000",      sizeof(c->provid)-1);
    strncpy(c->masterkey, "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F",
            sizeof(c->masterkey)-1);
    c->interval = 10;
}

void conf_load(tnfs_conf_t *c) {
    FILE *f = fopen(CONF_FILE, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char key[64], val[448];
        if (sscanf(line, " %63[^= ] = %447[^\r\n]", key, val) != 2) continue;
#define SET(field) strncpy(c->field, val, sizeof(c->field)-1); c->field[sizeof(c->field)-1] = 0
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
    fclose(f);
}
