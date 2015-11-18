#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM < 502
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

#define CLIENT "lcsock{client}"

#ifdef WIN32
#  include <windows.h>
#  include <winsock2.h>

static void startup()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		printf("WSAStartup failed with error: %d\n", err);
		exit(1);
	}
}

static void sleep_ms(int ms)
{
	Sleep(ms);
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

#define closesocket close

static void startup()
{
}

static void sleep_ms(int ms)
{
	usleep((useconds_t)ms * 1000);
}

#endif

#define CHECK_CLIENT(L, idx)\
	(*(sock_client_t **)luaL_checkudata(L, idx, CLIENT))

#define ENABLE_SOCK_DEBUG
#ifdef ENABLE_SOCK_DEBUG
# define DLOG(fmt, ...) fprintf(stderr, "<sock>" fmt "\n", ##__VA_ARGS__)
#else
# define DLOG(...)
#endif


static int fdcanread(int fd)
{
	int r = 0;
	fd_set rfds;
	struct timeval tv = { 0, 0 };

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	r = select(fd + 1, &rfds, NULL, NULL, &tv);
	DLOG("%s %d", __FUNCTION__, r);
	return r == 1;
}

typedef struct sock_client_s {
	int fd;
	int connected;
} sock_client_t;

static sock_client_t * sock_client_create()
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

static int lua__sleep(lua_State *L)
{
	int ms = luaL_optinteger(L, 1, 0);
	sleep_ms(ms);
	return 0;
}

static int lua__new(lua_State *L)
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
	client = sock_client_create();
	if (client == NULL) {
		closesocket(fd);
		lua_pushboolean(L, 0);
		lua_pushstring(L, "create client failed");
		return 2;
	}
	client->fd = fd;
	*p = client;
	luaL_getmetatable(L, CLIENT);
	lua_setmetatable(L, -2);
	return 1;
}

static int lua__connect(lua_State *L)
{
	int ret;
	struct sockaddr_in addr;
	sock_client_t * client = CHECK_CLIENT(L, 1);
	const char *addrstr = luaL_checkstring(L, 2);
	int port = luaL_checkinteger(L, 3);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(addrstr);
	addr.sin_port = htons(port);
	// memset(addr.sin_zero, 0x00, 8);

	ret = connect(client->fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, "connect %s:%d failed", addrstr, port);
		return 2;
	}
	client->connected = 1;
	lua_pushboolean(L, 1);
	return 1;
}

static int lua__isconnected(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	printf("%s %d\n", __FUNCTION__, client->connected);
	lua_pushboolean(L, client->connected);
	return 1;
}

static int lua__disconnect(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	closesocket(client->fd);
	client->connected = 0;
	return 0;
}

static int lua__read(lua_State *L)
{
	char tmp[8192];
	char *buf = (char *)&tmp;
	ssize_t rsz = 0;
	sock_client_t * client = CHECK_CLIENT(L, 1);
	size_t sz = luaL_optlong(L, 2, sizeof(tmp));
	if (!client->connected) {
		return luaL_error(L, "not connected");
	}
	if (!fdcanread(client->fd)) {
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
	} else if (rsz < 0) {
		client->connected = 0;
	}
	if (buf != (char *)&tmp) {
		free(buf);
	}
	return rsz > 0 ? 1 : 0;
}

static int lua__write(lua_State *L)
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

static int lua__gc(lua_State *L)
{
	sock_client_t * client = CHECK_CLIENT(L, 1);
	if (client != NULL) 
		free(client);
	return 0;
}


static int opencls__client(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"read", lua__read},
		{"write", lua__write},
		{"connect", lua__connect},
		{"isconnected", lua__isconnected},
		{"disconnect", lua__disconnect},
		{NULL, NULL},
	};
	luaL_newmetatable(L, CLIENT);
	lua_newtable(L);
	luaL_register(L, NULL, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

int luaopen_lcsock(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"new", lua__new},
		{"sleep", lua__sleep},
		{NULL, NULL},
	};
	startup();
	opencls__client(L);
	luaL_newlib(L, lfuncs);
	return 1;
}

