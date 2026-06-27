#include "platform.h"
#include "config.h"
#include "worker.h"
#include "log.h"
#include "version.h"

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
static HWND make_edit(HWND hWnd, int id, const char *def, int x, int y, int w, int h, DWORD xs) {
    HWND he = CreateWindowA("EDIT", def, WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|xs,
                            x, y, w, h, hWnd, (HMENU)(UINT_PTR)id, g_hInst, NULL);
    SendMessageA(he, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
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
    c->port     = atoi(portbuf);
    c->interval = atoi(ivbuf);
    c->is_tvcas4 = (SendMessageA(g_hwnd_chk_tvcas4, BM_GETCHECK, 0, 0) == BST_CHECKED);
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
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        const int lw=72, fw=290, sw=90, nw=72, x0=8, rh=24, rs=26;
        int y = 10;
        int xL1=x0, xF1=xL1+lw+4, xL2=xF1+fw+8, xF2=xL2+sw+4, xL3=xF2+sw+8, xF3=xL3+nw+4;
        make_label(hWnd,"HOST",   xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_HOST,  "127.0.0.1",xF1,y,fw,rh,0);
        make_label(hWnd,"PORT",   xL2,y+4,sw,16); make_edit(hWnd,IDC_EDIT_PORT,  "15050",    xF2,y,sw,rh,0);
        make_label(hWnd,"CAID",   xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_CAID,  "0B00",     xF3,y,nw,rh,0);
        y += rs;
        make_label(hWnd,"USER",   xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_USER,  "tvcas",    xF1,y,fw,rh,0);
        make_label(hWnd,"PASS",   xL2,y+4,sw,16); make_edit(hWnd,IDC_EDIT_PASS,  "1234",     xF2,y,sw,rh,0);
        make_label(hWnd,"SID",    xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_SID,   "0001",     xF3,y,nw,rh,0);
        y += rs;
        make_label(hWnd,"DES KEY",xL1,y+4,lw,16); make_edit(hWnd,IDC_EDIT_DESKEY,"0102030405060708091011121314",xF1,y,fw,rh,0);
        g_hwnd_chk_tvcas4 = CreateWindowA("BUTTON","TVCAS4",WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX,
            xL2,y+4,sw+4+sw,16,hWnd,(HMENU)(UINT_PTR)IDC_CHK_TVCAS4,g_hInst,NULL);
        SendMessageA(g_hwnd_chk_tvcas4,WM_SETFONT,(WPARAM)GetStockObject(DEFAULT_GUI_FONT),TRUE);
        make_label(hWnd,"PROVID",  xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_PROVID,"000000",  xF3,y,nw,rh,0);
        y += rs;
        int mk_w = xF2+sw-xF1;
        make_label(hWnd,"MASTER KEY",xL1,y+4,lw,16);
        make_edit(hWnd,IDC_EDIT_MASTERKEY,
            "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F",
            xF1,y,mk_w,rh,0);
        make_label(hWnd,"INTERVAL",xL3,y+4,nw,16); make_edit(hWnd,IDC_EDIT_INTERVAL,"10",    xF3,y,nw,rh,0);
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
        int w = rc.right-16, h = rc.bottom-140-8;
        if (g_hLog && h > 40) SetWindowPos(g_hLog,NULL,8,140,w,h,SWP_NOZORDER);
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
static GtkWidget  *g_chk_tvcas4;
static pthread_t   g_thread;
static volatile bool g_thread_running = false;
static worker_ctx_t *g_worker_ctx   = NULL;

static GtkWidget *mk_entry(const char *def, int chars) {
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e), def);
    gtk_entry_set_width_chars(GTK_ENTRY(e), chars);
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
    c->port = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_port)));
    strncpy(c->user,      gtk_entry_get_text(GTK_ENTRY(g_entry_user)),      sizeof(c->user)-1);
    strncpy(c->pass,      gtk_entry_get_text(GTK_ENTRY(g_entry_pass)),      sizeof(c->pass)-1);
    strncpy(c->deskey,    gtk_entry_get_text(GTK_ENTRY(g_entry_deskey)),    sizeof(c->deskey)-1);
    strncpy(c->caid,      gtk_entry_get_text(GTK_ENTRY(g_entry_caid)),      sizeof(c->caid)-1);
    strncpy(c->sid,       gtk_entry_get_text(GTK_ENTRY(g_entry_sid)),       sizeof(c->sid)-1);
    strncpy(c->provid,    gtk_entry_get_text(GTK_ENTRY(g_entry_provid)),    sizeof(c->provid)-1);
    strncpy(c->masterkey, gtk_entry_get_text(GTK_ENTRY(g_entry_masterkey)), sizeof(c->masterkey)-1);
    c->interval = atoi(gtk_entry_get_text(GTK_ENTRY(g_entry_interval)));
    c->is_tvcas4 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_chk_tvcas4));
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

    g_entry_host      = mk_entry("127.0.0.1", 30);
    g_entry_port      = mk_entry("15050",     12);
    g_entry_user      = mk_entry("tvcas",     30);
    g_entry_pass      = mk_entry("1234",      12);
    g_entry_interval  = mk_entry("10",         6);
    g_entry_deskey    = mk_entry("0102030405060708091011121314", 30);
    g_entry_caid      = mk_entry("0B00",   7);
    g_entry_sid       = mk_entry("0001",   7);
    g_entry_provid    = mk_entry("000000", 7);
    g_entry_masterkey = mk_entry(
        "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F", 46);

    gtk_widget_set_hexpand(g_entry_host,      TRUE);
    gtk_widget_set_hexpand(g_entry_user,      TRUE);
    gtk_widget_set_hexpand(g_entry_deskey,    TRUE);
    gtk_widget_set_hexpand(g_entry_masterkey, TRUE);

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
