/*
 *  An implementation of the ARC4 algorithm
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _RC4_H
#define _RC4_H

struct rc4_state {
	int x, y, m[256];
};

#ifdef __cplusplus
extern "C" {
#endif

void rc4_setup(struct rc4_state *s, unsigned char *key,  int length);
void rc4_crypt(struct rc4_state *s, unsigned char *data, int length);

#ifdef __cplusplus
}
#endif

#endif