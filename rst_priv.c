/* 
 * rst: TCP connect reset utility
 *
 * Aggressively resets TCP connections using TCP RST's or
 * ICMP.
 *
 * Copyright (c) 2005-2007 Michael Santos <michael.santos@gmail.com>
 *
 */
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "rst.h"

    int
rst_priv_drop(char *user, char *group, char *path)
{
    uid_t uid = 0;
    gid_t gid = 0;

    struct passwd *pwd = NULL;
    struct group *gr = NULL;

    if ( (user == NULL) || (group == NULL))
        return (-1);

    if ( (pwd = getpwnam(user)) == NULL) {
        warnx("user does not exist: %s", user);
        return (-1);
    }
    uid = pwd->pw_uid;

    if ( (gr = getgrnam(group)) == NULL) {
        warnx("group does not exist: %s", group);
        return (-1);
    }
    gid = gr->gr_gid;

    /* Disallow running as root */
    if (uid == 0) {
        warnx("refusing to running as root");
        return (-1);
    }

    if (chroot(path) != 0) {
        warnx("could not chroot: %s", RST_DIR);
        return (-1);
    }

    if (chdir("/") != 0) {
        warn("could not change to / in chroot");
        return (-1);
    }

    if (setgid(gid) != 0) {
        warnx("could not drop group privs");
        return (-1);
    }

    if (setuid(uid) != 0) {
        warnx("could not drop user privs");
        return (-1);
    }

    return (0);
}
