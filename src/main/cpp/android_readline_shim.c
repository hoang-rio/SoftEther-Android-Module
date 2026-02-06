/*
 * Android readline shim implementation
 * Provides stub implementations for readline functions not available in Bionic libc
 * These functions are not actually used in the Android VPN client context
 */

#include "android_readline_shim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* getch - get character from console without echoing
 * This is typically a Windows/PDCurses function.
 * On Android, we just return EOF since console input isn't used.
 */
int getch(void)
{
    return EOF;
}

/* readline - read a line from console with line editing
 * This is a GNU readline function.
 * On Android, we return NULL since console input isn't used.
 * The VPN client uses JNI for all input.
 */
char *readline(const char *prompt)
{
    if (prompt != NULL) {
        // Print prompt to stdout for debugging purposes
        printf("%s", prompt);
        fflush(stdout);
    }
    return NULL;
}

/* add_history - add a line to the readline history
 * This is a GNU readline function.
 * On Android, this is a no-op since readline isn't used.
 */
void add_history(const char *line)
{
    (void)line; // Suppress unused parameter warning
}
