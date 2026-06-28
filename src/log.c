#include "log.h"

#ifdef _WIN32

static HWND g_log_hwnd = NULL;

void log_init_ui(void *ui_handle) {
    g_log_hwnd = (HWND)ui_handle;
}

void log_append(const char *fmt, ...) {
    if (!g_log_hwnd) return;
    char ts[32], msg[1024], buf[1200];
    get_timestamp(ts, sizeof(ts));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(buf, sizeof(buf), "%s %s\r\n", ts, msg);
    int len = GetWindowTextLengthA(g_log_hwnd);
    SendMessageA(g_log_hwnd, EM_SETSEL,    (WPARAM)len, (LPARAM)len);
    SendMessageA(g_log_hwnd, EM_REPLACESEL, 0, (LPARAM)buf);
}

void log_clear(void) {
    if (!g_log_hwnd) return;
    SetWindowTextA(g_log_hwnd, "");
}

#else

#include <gtk/gtk.h>

typedef struct { char *text; } log_msg_t;

static GtkTextBuffer *g_log_buf  = NULL;
static GtkTextView   *g_log_view = NULL;
static GtkTextMark   *g_log_end  = NULL;

static gboolean log_idle(gpointer data) {
    log_msg_t *lm = (log_msg_t *)data;
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(g_log_buf, &end);
    gtk_text_buffer_insert(g_log_buf, &end, lm->text, -1);
    gtk_text_view_scroll_mark_onscreen(g_log_view, g_log_end);
    free(lm->text);
    free(lm);
    return FALSE;
}

void log_init_ui(void *ui_handle) {
    GtkWidget *view = (GtkWidget *)ui_handle;
    g_log_view = GTK_TEXT_VIEW(view);
    g_log_buf  = gtk_text_view_get_buffer(g_log_view);
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(g_log_buf, &end_iter);
    g_log_end = gtk_text_buffer_create_mark(g_log_buf, "end", &end_iter, FALSE);
}

void log_append(const char *fmt, ...) {
    char ts[32], msg[1024], full[1200];
    get_timestamp(ts, sizeof(ts));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(full, sizeof(full), "%s %s\n", ts, msg);
    log_msg_t *lm = (log_msg_t *)malloc(sizeof(log_msg_t));
    if (!lm) return;
    lm->text = strdup(full);
    if (!lm->text) { free(lm); return; }
    g_idle_add(log_idle, lm);
}

void log_clear(void) {
    if (!g_log_buf) return;
    gtk_text_buffer_set_text(g_log_buf, "", -1);
}

#endif
