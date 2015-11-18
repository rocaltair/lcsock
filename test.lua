l = require "lcsock"

local client = assert(l.new())
assert(client:connect("127.0.0.1", 8899))
client:disconnect()
while 1 do
	l.sleep(5)
	local data, err = client:read()
	if data then
		print(data)
		break
	end
end
client:write("hello world")
