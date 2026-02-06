/*
 * Android readline shim header
 * Android Bionic libc doesn't include readline, so we provide minimal stubs
 * These are not actually used in Android VPN client (uses JNI instead)
 */

#ifndef ANDROID_READLINE_SHIM_H
#define ANDROID_READLINE_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/* getch - get character from console (Windows/PDCurses function)
 * Not available on Android - stub returns EOF */
int getch(void);

/* readline - read a line from console with editing
 * Not available on Android - stub returns NULL */
char *readline(const char *prompt);

/* add_history - add line to readline history
 * Not available on Android - stub does nothing */
void add_history(const char *line);

#ifdef __cplusplus
}
#endif

#endif /* ANDROID_READLINE_SHIM_H */
