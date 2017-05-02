#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "lua.h"
#include "lauxlib.h"


#if (LUA_VERSION_NUM < 502 && !defined(luaL_newlib))
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

/**
 * #define ENABLE_SOCK_DEBUG
 */

#ifdef ENABLE_SOCK_DEBUG
# define LCS_DLOG(fmt, ...) fprintf(stderr, "<lcs>" fmt "\n", ##__VA_ARGS__)
#else
# define LCS_DLOG(...)
#endif


#define LCS_CLIENT "lcsock{client}"

#if (defined(WIN32) || defined(_WIN32))
# pragma comment (lib,"ws2_32.lib")
# include <windows.h>
# if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)
#  include <winsock2.h>
# endif

# ifndef socklen_t
#  define socklen_t short
# endif

# ifndef ssize_t
#  define ssize_t long
# endif

static void lcs_startup()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", err);
		exit(1);
	}
}

#define EINTR WSAEINTR
#define EWOULDBLOCK WSAEWOULDBLOCK

#else

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#ifndef closesocket
# define closesocket close
#endif

static void lcs_startup()
{
}

#endif

#define CHECK_CLIENT(L, idx)\
	(*(sock_client_t **)luaL_checkudata(L, idx, LCS_CLIENT))

static int lcs_fdcanread(int fd)
{
	int r = 0;
	fd_set rfds;
	struct timeval tv = { 0, 0 };

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	r = select(fd + 1, &rfds, NULL, NULL, &tv);
	/**
	 * LCS_DLOG("%s %d", __FUNCTION__, r);
	 */
	return r == 1;
}

typedef struct sock_client_s {
	int fd;
	int connected;
} sock_client_t;

static sock_client_t * lcsock_client_create()
{
	sock_client_t *p = malloc(sizeof(*p));
	if (p == NULL)
		goto nomem;
	p->fd = -1;
	p->connected = 0;
	return p;
nomem:
	return NULL;
}

static int lua__lcs_sleep(lua_State *L)
{
	int ms = luaL_optinteger(L, 1, 0);

#if (defined(WIN32) || defined(_WIN32))
	Sleep(ms);
#else
	usleep((useconds_t)ms * 1000);
#endif
	return 0;
}

static int lua__lcs_new(lua_State *L)
{
	int fd;
	sock_client_t **p;
	sock_client_t *client;
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd <= 0) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "create socket failed");
		return 2;
	}
	p = lua_newuserdata(L, sizeof(void *));
	client = lcsock_client_create();
	if (client == NULL) {
		closesocket(fd);
		lua_pushboolean(L, 0);
		lua_pushstring(L, "create client failed");
		return 2;
	}
	client->fd = fd;
	*p = client;
	luaL_getmetatable(L, LCS_CLIENT);
	lua_setmetatable(L, -2);
	return 1;
}

static int lua__lcs_setsockopt(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	const char *optstr = luaL_checkstring(L, 2);
	lua_Number tv = luaL_checknumber(L, 3);
	int rc;
	int opt = 0;
#if (defined(WIN32) || defined(_WIN32))
	int timeout = (int)tv;
#else
	struct timeval timeout ={
		(int)tv/1000,
		(((int)tv) % 1000) * 1e6
	};
#endif

	if (strcmp(optstr, "RCVTIMEO") == 0) {
		opt = SO_RCVTIMEO;
	} else if(strcmp(optstr, "SNDTIMEO") == 0) {
		opt = SO_SNDTIMEO;
	} else {
		return luaL_argerror(L, 2, "unknown opt");
	}

	rc = setsockopt(client->fd,
			SOL_SOCKET,
			opt,
			(const char*)&timeout,
			sizeof(timeout));
	lua_pushboolean(L, rc == 0);
	return 1;
}

static int setnonblock(int fd)
{
#if (!(defined(WIN32) || defined(_WIN32)))
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	return flags;
#else
	int flags = 1;
	ioctlsocket(fd, FIONBIO, (u_long FAR*)&flags);
	return 0;
#endif
}

static void restoreflags(int fd, int flags)
{
#if (!(defined(WIN32) || defined(_WIN32)))
	fcntl(fd, F_SETFL, flags);
#else
	u_long mode = flags;
	flags = 0;
	ioctlsocket(fd, FIONBIO, (u_long FAR*)&mode);
#endif
}

static int connect_nonb(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int msec)
{
	int flags, n, error;
	socklen_t len;
	fd_set rset, wset;
	struct timeval tval;

	flags = setnonblock(sockfd);

	error = 0;
	if ((n = connect(sockfd, addr, addrlen)) < 0){
#if (!(defined(WIN32) || defined(_WIN32)))
		if (errno != EINPROGRESS)
			return -1;
#endif
	}
	fprintf(stderr, "connect end\n");

	if (n == 0)
		goto done;               /* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = msec / 1000;
	tval.tv_usec = msec % 1000;

	fprintf(stderr, "start select\n");
	if ( (n = select(sockfd + 1, &rset, &wset, NULL,
					msec ? &tval : NULL)) == 0) {
#if (!(defined(WIN32) || defined(_WIN32)))
		errno = ETIMEDOUT;
#endif
		return -1;
	}
	fprintf(stderr, "end select\n");

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			/* Solaris pending error */
			return -1;
	} else {
		fprintf(stderr, "select error: sockfd not set");
		return -1;
	}

done:
	/* restore file status flags */
	restoreflags(sockfd, flags);

	if (error) {
#if (!(defined(WIN32) || defined(_WIN32)))
		errno = error;
#endif
		return -1;
	}
	return 0;
}

static int lua__lcs_connect(lua_State *L)
{
	int ret;
	struct sockaddr_in addr;
	sock_client_t * client = CHECK_CLIENT(L, 1);
	const char *addrstr = luaL_checkstring(L, 2);
	int port = luaL_checkinteger(L, 3);
	int timeout = luaL_optinteger(L, 4, 1000);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(addrstr);
	addr.sin_port = htons(port);

	/* ret = connect(client->fd, (struct sockaddr *)&addr, sizeof(addr)); */
	ret = connect_nonb(client->fd, (const struct sockaddr *)&addr, sizeof(addr), timeout);
	if (ret != 0) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, "connect %s:%d failed", addrstr, port);
		return 2;
	}
	client->connected = 1;
	lua_pushboolean(L, 1);
	return 1;
}

static int lua__lcs_isconnected(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	LCS_DLOG("%s %d", __FUNCTION__, client->connected);
	lua_pushboolean(L, client->connected);
	return 1;
}

static int lua__lcs_disconnect(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	closesocket(client->fd);
	client->connected = 0;
	return 0;
}

static int lua__lcs_read(lua_State *L)
{
	char tmp[8192];
	char *buf = (char *)&tmp;
	ssize_t rsz = 0;
	sock_client_t * client = CHECK_CLIENT(L, 1);
	size_t sz = luaL_optlong(L, 2, sizeof(tmp));
	if (!client->connected) {
		return luaL_error(L, "not connected");
	}
	if (!lcs_fdcanread(client->fd)) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "no data");
		return 2;
	}
	if (sz > sizeof(tmp)) {
		buf = malloc(sz);
		if (buf == NULL) {
			return luaL_error(L, "nomem while read");
		}
	}

	rsz = recv(client->fd, buf, sz, 0);
	if (rsz > 0) {
		lua_pushlstring(L, buf, rsz);
	} else if (rsz <= 0) {
		client->connected = 0;
	}
	if (buf != (char *)&tmp) {
		free(buf);
	}
	return rsz > 0 ? 1 : 0;
}

static int lua__lcs_write(lua_State *L)
{
	size_t sz;
	size_t p = 0;
	sock_client_t * client = CHECK_CLIENT(L, 1);
	const char *buf = luaL_checklstring(L, 2, &sz);
	if (!client->connected) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "not connected");
		return 2;
	}
	for (;;) {
		int wt = send(client->fd, buf + p, sz - p, 0);
		if (wt < 0) {
			switch (errno) {
			case EWOULDBLOCK:
			case EINTR:
				continue;
			default:
				closesocket(client->fd);
				client->fd = -1;
				client->connected = 0;
				lua_pushboolean(L, 0);
				return 1;
			}
		}
		if (wt == sz - p)
			break;
		p += wt;
	}
	lua_pushboolean(L, 1);
	return 1;
}

static int lua__lcs_gc(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	if (client != NULL)
		free(client);
	LCS_DLOG("client gc");
	return 0;
}

static int luac__lcs_is_classtype(lua_State *L, int idx, const char *classType)
{
	int ret = 0;
	int top = lua_gettop(L);
	int mt = lua_getmetatable(L, idx);
	if (mt == 0) {
		goto finished;
	}
	luaL_getmetatable(L, classType);
	if (lua_equal(L, -1, -2)) {
		ret = 1;
	}
finished:
	lua_settop(L, top);
	return ret;
}

static int lua__lcs_is_client(lua_State *L)
{
	int ret = luac__lcs_is_classtype(L, 1, LCS_CLIENT);
	lua_pushboolean(L, ret);
	return 1;
}

static int opencls__client(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"read", lua__lcs_read},
		{"write", lua__lcs_write},
		{"setsockopt", lua__lcs_setsockopt},
		{"connect", lua__lcs_connect},
		{"isconnected", lua__lcs_isconnected},
		{"disconnect", lua__lcs_disconnect},
		{NULL, NULL},
	};
	luaL_newmetatable(L, LCS_CLIENT);
	luaL_newlib(L, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__lcs_gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

int luaopen_lcsock(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"new", lua__lcs_new},
		{"sleep", lua__lcs_sleep},
		{"is_client", lua__lcs_is_client},
		{NULL, NULL},
	};
	lcs_startup();
	opencls__client(L);
	luaL_newlib(L, lfuncs);
	return 1;
}
