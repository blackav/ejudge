/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __AGENT_SERVER_H__
#define __AGENT_SERVER_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

typedef struct AgentServerParams
{
} AgentServerParams;

int agent_server_start(const AgentServerParams *params);

#endif /* __AGENT_SERVER_H__ */
