/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _IPGUARD_CLIENT_H
#define _IPGUARD_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#define IPGUARD_DEF_SOCKET_PATH	"/var/run/ipguard.sock"
#define IPGUARD_DEF_ENABLE		0
#define IPGUARD_DEF_DEBUG		0
#define IPGUARD_DEF_RESTRICTIVE	1

#define IPGUARD_SYSFAIL		(-1)
#define IPGUARD_OK			0
#define IPGUARD_FORBIDDEN	1

int ipguard_check_ipaddr (const char *ipaddr, char *answer, int answer_len);
int ipguard_check_ip (unsigned long ip, char *answer, int answer_len);
int ipguard_set_debug (int debug);
int ipguard_set_restrictive (int restrictive);
int ipguard_set_enable (int enable);
int ipguard_set_socket_path (const char *socket_path);

#ifdef __cplusplus
}
#endif

#endif /* IPGUARD_CLIENT_H */

