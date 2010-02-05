/* Copyright (c) 2005-2010, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * rst: TCP connect reset utility
 *
 * Aggressively resets TCP connections using TCP RST's or
 * ICMP.
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
