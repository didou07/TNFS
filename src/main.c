#include "platform.h"
#include "config.h"
#include "worker.h"
#include "log.h"
#include "version.h"

static int clamp_int(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static long days_from_civil(int y, int m, int d) {
    y -= (m <= 2);
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe/4 - yoe/100 + doy;
    return era * 146097 + (long)doe - 719468;
}

static void ymdhms_to_ts_str(int y, int mo, int d, int h, int mi, int se, char *out, size_t outsz) {
    if (y <= 0 || mo <= 0 || d <= 0) { out[0] = '\0'; return; }
    y  = clamp_int(y,  1970, 2099);
    mo = clamp_int(mo, 1, 12);
    d  = clamp_int(d,  1, 31);
    h  = clamp_int(h,  0, 23);
    mi = clamp_int(mi, 0, 59);
    se = clamp_int(se, 0, 59);
    long days = days_from_civil(y, mo, d);
    long long unix_ts = (long long)days * 86400LL + h * 3600LL + mi * 60LL + se;
    snprintf(out, outsz, "%lld", unix_ts);
}

static void ts_str_to_ymdhms(const char *ts_str, int *y, int *mo, int *d, int *h, int *mi, int *se) {
    *y = *mo = *d = *h = *mi = *se = 0;
    if (!ts_str || ts_str[0] == '\0') return;
    long long t = atoll(ts_str);
    if (t <= 0) return;
    long days = (long)(t / 86400);
    long rem  = (long)(t % 86400);
    if (rem < 0) { rem += 86400; days--; }
    *h = (int)(rem / 3600); rem %= 3600;
    *mi = (int)(rem / 60);
    *se = (int)(rem % 60);
    long z = days + 719468;
    long era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    long yy = (long)yoe + era * 400;
    unsigned doy = doe - (365*yoe + yoe/4 - yoe/100);
    unsigned mp = (5*doy + 2)/153;
    unsigned dd = doy - (153*mp+2)/5 + 1;
    unsigned mm = mp + (mp < 10 ? 3 : -9);
    yy += (mm <= 2);
    *y = (int)yy; *mo = (int)mm; *d = (int)dd;
}

#ifdef _WIN32

#define IDC_EDIT_HOST      101
#define IDC_EDIT_PORT      102
#define IDC_EDIT_USER      103
#define IDC_EDIT_PASS      104
#define IDC_EDIT_DESKEY    105
#define IDC_EDIT_CAID      106
#define IDC_EDIT_SID       107
#define IDC_EDIT_PROVID    108
#define IDC_EDIT_MASTERKEY 109
#define IDC_EDIT_INTERVAL  110
#define IDC_BTN_RUN        111
#define IDC_BTN_STOP       112
#define IDC_BTN_CLEAR      113
#define IDC_EDIT_LOG       114
#define IDC_CHK_TVCAS4     115
#define IDC_EDIT_YEAR      118
#define IDC_EDIT_MONTH     119
#define IDC_EDIT_DAY       120
#define IDC_EDIT_AC        117

static HINSTANCE g_hInst;
static HWND      g_hWnd;
static HWND      g_hLog;
static HWND      g_hwnd_chk_tvcas4;
static HANDLE    g_thread      = NULL;
static volatile  LONG g_worker_stop = 0;
static volatile  LONG g_thread_running = 0;
static worker_ctx_t  *g_worker_ctx  = NULL;

static HWND make_label(HWND hWnd, const char *text, int x, int y, int w, int h) {
    return CreateWindowA("STATIC", text, WS_VISIBLE|WS_CHILD|SS_LEFT,
                         x, y, w, h, hWnd, NULL, g_hInst, NULL);
}
static DWORD WINAPI worker_thread_trampoline(LPVOID arg) {
    worker_thread(arg);
    g_worker_ctx = NULL;
    InterlockedExchange(&g_thread_running, 0);
    return 0;
}
static HWND make_edit(HWND hWnd, int id, const char *def, int x, int y, int w, int h, DWORD xs, int maxlen) {
    HWND he = CreateWindowA("EDIT", def, WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|xs,
                            x, y, w, h, hWnd, (HMENU)(UINT_PTR)id, g_hInst, NULL);
    SendMessageA(he, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    if (maxlen > 0) SendMessageA(he, EM_SETLIMITTEXT, (WPARAM)maxlen, 0);
    return he;
}
static HWND make_btn(HWND hWnd, int id, const char *text, int x, int y, int w, int h) {
    HWND hb = CreateWindowA("BUTTON", text, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,
                            x, y, w, h, hWnd, (HMENU)(UINT_PTR)id, g_hInst, NULL);
    SendMessageA(hb, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return hb;
}

static void gui_read_conf(HWND hWnd, tnfs_conf_t *c) {
    char portbuf[16], ivbuf[16];
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_HOST),      c->host,      sizeof(c->host));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PORT),      portbuf,      sizeof(portbuf));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_USER),      c->user,      sizeof(c->user));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASS),      c->pass,      sizeof(c->pass));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DESKEY),    c->deskey,    sizeof(c->deskey));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_CAID),      c->caid,      sizeof(c->caid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_SID),       c->sid,       sizeof(c->sid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PROVID),    c->provid,    sizeof(c->provid));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MASTERKEY), c->masterkey, sizeof(c->masterkey));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_INTERVAL),  ivbuf,        sizeof(ivbuf));
    c->port     = clamp_int(atoi(portbuf), 1, 65535);
    c->interval = clamp_int(atoi(ivbuf), 1, 3600);
    c->is_tvcas4 = (SendMessageA(g_hwnd_chk_tvcas4, BM_GETCHECK, 0, 0) == BST_CHECKED);
    {
        char yb[8], mob[4], db[4];
        GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_YEAR),   yb,  sizeof(yb));
        GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MONTH),  mob, sizeof(mob));
        GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DAY),    db,  sizeof(db));
        ymdhms_to_ts_str(atoi(yb), atoi(mob), atoi(db), 0, 0, 0,
                         c->timestamp, sizeof(c->timestamp));
    }
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_AC), c->access_criteria, sizeof(c->access_criteria));
}
static void gui_write_conf(HWND hWnd, const tnfs_conf_t *c) {
    char portbuf[16], ivbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", c->port);
    snprintf(ivbuf,   sizeof(ivbuf),   "%d", c->interval);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_HOST),      c->host);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PORT),      portbuf);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_USER),      c->user);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASS),      c->pass);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_DESKEY),    c->deskey);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_CAID),      c->caid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_SID),       c->sid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PROVID),    c->provid);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_MASTERKEY), c->masterkey);
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_INTERVAL),  ivbuf);
    SendMessageA(g_hwnd_chk_tvcas4, BM_SETCHECK, c->is_tvcas4 ? BST_CHECKED : BST_UNCHECKED, 0);
    {
        int y,mo,d,h,mi,se; char b[16];
        ts_str_to_ymdhms(c->timestamp, &y, &mo, &d, &h, &mi, &se);
        if (y) { snprintf(b,sizeof(b),"%d",y);  SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_YEAR),   b); }
        else                                     SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_YEAR),   "");
        if (mo){ snprintf(b,sizeof(b),"%d",mo); SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_MONTH),  b); }
        else                                     SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_MONTH),  "");
        if (d) { snprintf(b,sizeof(b),"%d",d);  SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_DAY),    b); }
        else                                     SetWindowTextA(GetDlgItem(hWnd,IDC_EDIT_DAY),    "");
    }
    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_AC), c->access_criteria);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        const int lw=72, fw=290, sw=90, nw=72, x0=8, rh=24, rs=26;
        int y = 10;
        int xL1=x0, xF1=xL1+lw+4, xL2=xF1+fw+8, xF2=xL2+sw+4, xL3=xF2+sw+8, xF3=xL3+nw+4;
        make_label(hWnd,"HOST",   xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_HOST,  "127.0.0.1",xF1,y,fw,rh,0,255);
        make_label(hWnd,"PORT",   xL2,y+4,sw,16); make_edit(hWnd,IDC_EDIT_PORT,  "15050",    xF2,y,sw,rh,ES_NUMBER,5);
        make_label(hWnd,"CAID",   xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_CAID,  "0B00",     xF3,y,nw,rh,0,4);
        y += rs;
        make_label(hWnd,"USER",   xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_USER,  "tvcas",    xF1,y,fw,rh,0,63);
        make_label(hWnd,"PASS",   xL2,y+4,sw,16); make_edit(hWnd,IDC_EDIT_PASS,  "1234",     xF2,y,sw,rh,0,63);
        make_label(hWnd,"SID",    xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_SID,   "0001",     xF3,y,nw,rh,0,4);
        y += rs;
        make_label(hWnd,"DES KEY",xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_DESKEY,"0102030405060708091011121314",xF1,y,fw,rh,0,28);
        g_hwnd_chk_tvcas4 = CreateWindowA("BUTTON","TVCAS4",WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
            xL2,y+4,sw+4+sw,16,hWnd,(HMENU)(UINT_PTR)IDC_CHK_TVCAS4,g_hInst,NULL);
        SendMessageA(g_hwnd_chk_tvcas4,WM_SETFONT,(WPARAM)GetStockObject(DEFAULT_GUI_FONT),TRUE);
        make_label(hWnd,"PROVID",  xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_PROVID,"000000",  xF3,y,nw,rh,0,6);
        y += rs;
        int mk_w = xF2+sw-xF1;
        make_label(hWnd,"MASTER KEY",xL1,y+4,lw,16);
        make_edit(hWnd,IDC_EDIT_MASTERKEY,
            "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F",
            xF1,y,mk_w,rh,0,64);
        make_label(hWnd,"INTERVAL",xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_INTERVAL,"10",    xF3,y,nw,rh,ES_NUMBER,4);
        y += rs;
        make_label(hWnd,"DATE",xL1,y+4,lw,16);
        {
            int bw = 44, gap = 6, bx = xF1;
            make_edit(hWnd,IDC_EDIT_YEAR,  "",bx,y,bw,rh,ES_NUMBER,4); bx += bw+gap;
            make_edit(hWnd,IDC_EDIT_MONTH, "",bx,y,bw,rh,ES_NUMBER,2); bx += bw+gap;
            make_edit(hWnd,IDC_EDIT_DAY,   "",bx,y,bw,rh,ES_NUMBER,2);
        }
        {
            int acLabelW = 100;
            int acFieldX = xL2 + acLabelW + 4;
            int acFieldW = (xF3+nw) - acFieldX;
            make_label(hWnd,"ACCESS CRITERIA",xL2,y+4,acLabelW,16);
            make_edit(hWnd,IDC_EDIT_AC,"",acFieldX,y,acFieldW,rh,0,8);
        }
        y += rs+6;
        make_btn(hWnd,IDC_BTN_RUN,  "Run Test", x0,    y,90,26);
        make_btn(hWnd,IDC_BTN_STOP, "Stop",     x0+98, y,72,26);
        make_btn(hWnd,IDC_BTN_CLEAR,"Clear Log",x0+178,y,82,26);
        y += 34;
        g_hLog = CreateWindowA("EDIT","",
            WS_VISIBLE|WS_CHILD|WS_BORDER|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
            8,y,1,1,hWnd,(HMENU)(UINT_PTR)IDC_EDIT_LOG,g_hInst,NULL);
        SendMessageA(g_hLog,WM_SETFONT,(WPARAM)CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH|FF_MODERN,"Consolas"),TRUE);
        log_init_ui(g_hLog);
        tnfs_conf_t c; conf_defaults(&c); conf_load(&c); gui_write_conf(hWnd, &c);
        log_append("Ready -- fill fields and click Run Test.");
        break;
    }
    case WM_SIZE: {
        RECT rc; GetClientRect(hWnd, &rc);
        int w = rc.right-16, h = rc.bottom-166-8;
        if (g_hLog && h > 40) SetWindowPos(g_hLog,NULL,8,166,w,h,SWP_NOZORDER);
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_RUN:
            if (InterlockedCompareExchange(&g_thread_running, 0, 0)) { log_append("[!] Already running -- click Stop first."); break; }
            {
                tnfs_conf_t c; gui_read_conf(hWnd, &c); conf_save(&c);
                worker_ctx_t *ctx = (worker_ctx_t *)calloc(1, sizeof(worker_ctx_t));
                memcpy(ctx->params.host,      c.host,      sizeof(c.host));
                ctx->params.port = c.port;
                memcpy(ctx->params.user,      c.user,      sizeof(c.user));
                memcpy(ctx->params.pass,      c.pass,      sizeof(c.pass));
                memcpy(ctx->params.deskey,    c.deskey,    sizeof(c.deskey));
                memcpy(ctx->params.caid,      c.caid,      sizeof(c.caid));
                memcpy(ctx->params.sid,       c.sid,       sizeof(c.sid));
                memcpy(ctx->params.provid,    c.provid,    sizeof(c.provid));
                memcpy(ctx->params.masterkey, c.masterkey, sizeof(c.masterkey));
                ctx->params.ecm_interval_sec = c.interval;
                ctx->params.is_tvcas4 = (SendMessageA(g_hwnd_chk_tvcas4,BM_GETCHECK,0,0)==BST_CHECKED);
                memcpy(ctx->params.timestamp,       c.timestamp,       sizeof(c.timestamp));
                memcpy(ctx->params.access_criteria, c.access_criteria, sizeof(c.access_criteria));
                g_worker_ctx = ctx;
                InterlockedExchange(&g_thread_running, 1);
                g_thread = CreateThread(NULL, 0, worker_thread_trampoline, ctx, 0, NULL);
            }
            break;
        case IDC_BTN_STOP:
            if (g_worker_ctx) g_worker_ctx->stop = 1;
            break;
        case IDC_BTN_CLEAR:
            log_clear();
            break;
        }
        break;
    case WM_DESTROY:
        { tnfs_conf_t c; gui_read_conf(hWnd, &c); conf_save(&c); }
        if (g_worker_ctx) g_worker_ctx->stop = 1;
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    g_hInst = hInstance;
    WSADATA wsaData; WSAStartup(MAKEWORD(2,2), &wsaData);
    srand((unsigned)time(NULL));
    WNDCLASSEXA wc = {0};
    wc.cbSize=sizeof(wc); wc.lpfnWndProc=WndProc; wc.hInstance=hInstance;
    wc.hIcon=LoadIcon(NULL,IDI_APPLICATION); wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1); wc.lpszClassName="TNFSClass";
    RegisterClassExA(&wc);
    g_hWnd = CreateWindowExA(0,"TNFSClass",APP_TITLE " (TNFS)",
        WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,760,560,NULL,NULL,hInstance,NULL);
    ShowWindow(g_hWnd,nCmdShow); UpdateWindow(g_hWnd);
    MSG msg;
    while (GetMessageA(&msg,NULL,0,0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    WSACleanup();
    return (int)msg.wParam;
}

#else

#include <gtk/gtk.h>

static GtkWidget  *g_entry_host, *g_entry_port, *g_entry_user, *g_entry_pass;
static GtkWidget  *g_entry_deskey, *g_entry_caid, *g_entry_sid;
static GtkWidget  *g_entry_provid, *g_entry_masterkey, *g_entry_interval;
static GtkWidget  *g_entry_year, *g_entry_month, *g_entry_day, *g_entry_ac;
static GtkWidget  *g_chk_tvcas4;
static pthread_t   g_thread;
static volatile bool g_thread_running = false;
static worker_ctx_t *g_worker_ctx   = NULL;

static GtkWidget *mk_entry(const char *def, int chars, int maxlen) {
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e), def);
    gtk_entry_set_width_chars(GTK_ENTRY(e), chars);
    if (maxlen > 0) gtk_entry_set_max_length(GTK_ENTRY(e), maxlen);
    return e;
}
static GtkWidget *mk_label(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_widget_set_halign(l, GTK_ALIGN_END);
    return l;
}

static void gtk_collect_conf(tnfs_conf_t *c) {
    memset(c, 0, sizeof(*c));
    strncpy(c->host,      gtk_entry_get_text(GTK_ENTRY(g_entry_host)),      sizeof(c->host)-1);
    c->port = clamp_int(atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_port))), 1, 65535);
    strncpy(c->user,      gtk_entry_get_text(GTK_ENTRY(g_entry_user)),      sizeof(c->user)-1);
    strncpy(c->pass,      gtk_entry_get_text(GTK_ENTRY(g_entry_pass)),      sizeof(c->pass)-1);
    strncpy(c->deskey,    gtk_entry_get_text(GTK_ENTRY(g_entry_deskey)),    sizeof(c->deskey)-1);
    strncpy(c->caid,      gtk_entry_get_text(GTK_ENTRY(g_entry_caid)),      sizeof(c->caid)-1);
    strncpy(c->sid,       gtk_entry_get_text(GTK_ENTRY(g_entry_sid)),       sizeof(c->sid)-1);
    strncpy(c->provid,    gtk_entry_get_text(GTK_ENTRY(g_entry_provid)),    sizeof(c->provid)-1);
    strncpy(c->masterkey, gtk_entry_get_text(GTK_ENTRY(g_entry_masterkey)), sizeof(c->masterkey)-1);
    c->interval = clamp_int(atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_interval))), 1, 3600);
    c->is_tvcas4 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_chk_tvcas4));
    ymdhms_to_ts_str(
        atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_year))),
        atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_month))),
        atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_day))),
        0, 0, 0,
        c->timestamp, sizeof(c->timestamp));
    strncpy(c->access_criteria, gtk_entry_get_text(GTK_ENTRY(g_entry_ac)), sizeof(c->access_criteria)-1);
}
static void gtk_populate_conf(const tnfs_conf_t *c) {
    char portbuf[16], ivbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", c->port);
    snprintf(ivbuf,   sizeof(ivbuf),   "%d", c->interval);
    gtk_entry_set_text(GTK_ENTRY(g_entry_host),      c->host);
    gtk_entry_set_text(GTK_ENTRY(g_entry_port),      portbuf);
    gtk_entry_set_text(GTK_ENTRY(g_entry_user),      c->user);
    gtk_entry_set_text(GTK_ENTRY(g_entry_pass),      c->pass);
    gtk_entry_set_text(GTK_ENTRY(g_entry_deskey),    c->deskey);
    gtk_entry_set_text(GTK_ENTRY(g_entry_caid),      c->caid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_sid),       c->sid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_provid),    c->provid);
    gtk_entry_set_text(GTK_ENTRY(g_entry_masterkey), c->masterkey);
    gtk_entry_set_text(GTK_ENTRY(g_entry_interval),  ivbuf);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_chk_tvcas4), c->is_tvcas4);
    {
        int y,mo,d,h,mi,se; char b[16];
        ts_str_to_ymdhms(c->timestamp, &y, &mo, &d, &h, &mi, &se);
        if (y)  { snprintf(b,sizeof(b),"%d",y);  gtk_entry_set_text(GTK_ENTRY(g_entry_year),  b); }
        else                                       gtk_entry_set_text(GTK_ENTRY(g_entry_year),  "");
        if (mo) { snprintf(b,sizeof(b),"%d",mo); gtk_entry_set_text(GTK_ENTRY(g_entry_month), b); }
        else                                       gtk_entry_set_text(GTK_ENTRY(g_entry_month), "");
        if (d)  { snprintf(b,sizeof(b),"%d",d);  gtk_entry_set_text(GTK_ENTRY(g_entry_day),   b); }
        else                                       gtk_entry_set_text(GTK_ENTRY(g_entry_day),   "");
    }
    gtk_entry_set_text(GTK_ENTRY(g_entry_ac), c->access_criteria);
}

static void *worker_thread_trampoline(void *arg) {
    worker_thread(arg);
    g_thread_running = false;
    g_worker_ctx     = NULL;
    return NULL;
}

static void on_run_clicked(GtkButton *btn, gpointer ud) {
    (void)btn; (void)ud;
    if (g_thread_running) { log_append("[!] Already running -- click Stop first."); return; }
    tnfs_conf_t c; gtk_collect_conf(&c); conf_save(&c);
    worker_ctx_t *ctx = (worker_ctx_t *)calloc(1, sizeof(worker_ctx_t));
    memcpy(ctx->params.host,      c.host,      sizeof(c.host));
    ctx->params.port = c.port;
    memcpy(ctx->params.user,      c.user,      sizeof(c.user));
    memcpy(ctx->params.pass,      c.pass,      sizeof(c.pass));
    memcpy(ctx->params.deskey,    c.deskey,    sizeof(c.deskey));
    memcpy(ctx->params.caid,      c.caid,      sizeof(c.caid));
    memcpy(ctx->params.sid,       c.sid,       sizeof(c.sid));
    memcpy(ctx->params.provid,    c.provid,    sizeof(c.provid));
    memcpy(ctx->params.masterkey, c.masterkey, sizeof(c.masterkey));
    ctx->params.ecm_interval_sec = c.interval;
    ctx->params.is_tvcas4 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_chk_tvcas4));
    memcpy(ctx->params.timestamp,       c.timestamp,       sizeof(c.timestamp));
    memcpy(ctx->params.access_criteria, c.access_criteria, sizeof(c.access_criteria));
    g_worker_ctx    = ctx;
    g_thread_running = true;
    pthread_create(&g_thread, NULL, worker_thread_trampoline, ctx);
    pthread_detach(g_thread);
}
static void on_stop_clicked(GtkButton *btn, gpointer ud) {
    (void)btn; (void)ud;
    if (g_worker_ctx) g_worker_ctx->stop = 1;
}
static void on_clear_clicked(GtkButton *btn, gpointer ud) {
    (void)btn; (void)ud;
    log_clear();
}
static gboolean on_delete_event(GtkWidget *w, GdkEvent *ev, gpointer d) {
    (void)w; (void)ev; (void)d;
    if (g_worker_ctx) g_worker_ctx->stop = 1;
    tnfs_conf_t c; gtk_collect_conf(&c); conf_save(&c);
    return FALSE;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    srand((unsigned)time(NULL));

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), APP_TITLE " (TNFS)");
    gtk_window_set_default_size(GTK_WINDOW(window), 860, 520);
    g_signal_connect(window, "destroy",      G_CALLBACK(gtk_main_quit),   NULL);
    g_signal_connect(window, "delete-event", G_CALLBACK(on_delete_event), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    g_entry_year   = mk_entry("", 4, 4);
    g_entry_month  = mk_entry("", 2, 2);
    g_entry_day    = mk_entry("", 2, 2);
    g_entry_ac     = mk_entry("", 12, 8);
    g_entry_host      = mk_entry("127.0.0.1", 30, 255);
    g_entry_port      = mk_entry("15050",     12, 5);
    g_entry_user      = mk_entry("tvcas",     30, 63);
    g_entry_pass      = mk_entry("1234",      12, 63);
    g_entry_interval  = mk_entry("10",         6, 4);
    g_entry_deskey    = mk_entry("0102030405060708091011121314", 30, 28);
    g_entry_caid      = mk_entry("0B00",   7, 4);
    g_entry_sid       = mk_entry("0001",   7, 4);
    g_entry_provid    = mk_entry("000000", 7, 6);
    g_entry_masterkey = mk_entry(
        "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F", 46, 64);

    gtk_widget_set_hexpand(g_entry_host,      TRUE);
    gtk_widget_set_hexpand(g_entry_user,      TRUE);
    gtk_widget_set_hexpand(g_entry_deskey,    TRUE);
    gtk_widget_set_hexpand(g_entry_masterkey, TRUE);
    gtk_widget_set_hexpand(g_entry_ac,        TRUE);

    gtk_grid_attach(GTK_GRID(grid), mk_label("HOST"),  0,0,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_host,      1,0,1,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("PORT"),  2,0,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_port,      3,0,1,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("CAID"),  4,0,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_caid,      5,0,1,1);

    gtk_grid_attach(GTK_GRID(grid), mk_label("USER"),  0,1,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_user,      1,1,1,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("PASS"),  2,1,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_pass,      3,1,1,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("SID"),   4,1,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_sid,       5,1,1,1);

    gtk_grid_attach(GTK_GRID(grid), mk_label("DES KEY"), 0,2,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_deskey,      1,2,1,1);
    g_chk_tvcas4 = gtk_check_button_new_with_label("TVCAS4 key");
    gtk_grid_attach(GTK_GRID(grid), g_chk_tvcas4,        2,2,2,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("PROVID"),  4,2,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_provid,      5,2,1,1);

    gtk_grid_attach(GTK_GRID(grid), mk_label("MASTER KEY"), 0,3,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_masterkey,      1,3,3,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("INTERVAL"),   4,3,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_interval,       5,3,1,1);

    GtkWidget *date_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_box_pack_start(GTK_BOX(date_box), g_entry_year,   FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(date_box), g_entry_month,  FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(date_box), g_entry_day,    FALSE,FALSE,0);
    gtk_grid_attach(GTK_GRID(grid), mk_label("DATE"),           0,4,1,1);
    gtk_grid_attach(GTK_GRID(grid), date_box,                   1,4,1,1);
    gtk_grid_attach(GTK_GRID(grid), mk_label("ACCESS CRITERIA"),2,4,1,1);
    gtk_grid_attach(GTK_GRID(grid), g_entry_ac,                 3,4,3,1);

    tnfs_conf_t c; conf_defaults(&c); conf_load(&c); gtk_populate_conf(&c);

    GtkWidget *btnbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), btnbox, FALSE, FALSE, 2);
    GtkWidget *btn_run   = gtk_button_new_with_label("Run Test");
    GtkWidget *btn_stop  = gtk_button_new_with_label("Stop");
    GtkWidget *btn_clear = gtk_button_new_with_label("Clear Log");
    g_signal_connect(btn_run,   "clicked", G_CALLBACK(on_run_clicked),   NULL);
    g_signal_connect(btn_stop,  "clicked", G_CALLBACK(on_stop_clicked),  NULL);
    g_signal_connect(btn_clear, "clicked", G_CALLBACK(on_clear_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btnbox), btn_run,   FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(btnbox), btn_stop,  FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(btnbox), btn_clear, FALSE,FALSE,0);

    gtk_box_pack_start(GTK_BOX(vbox), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,FALSE,0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    GtkWidget *log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(log_view), TRUE);
    log_init_ui(log_view);
    gtk_container_add(GTK_CONTAINER(scroll), log_view);
    gtk_widget_set_size_request(scroll, -1, 300);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    gtk_widget_show_all(window);
    log_append("Ready. Fill fields and click Run Test.");
    gtk_main();
    return 0;
}

#endif
