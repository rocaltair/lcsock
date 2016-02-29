l = require "lcsock"

local client = assert(l.new())
assert(client:connect("127.0.0.1", 8899))
-- client:disconnect()
while client:isconnected() do
	l.sleep(5)
	local data, err = client:read()
	if data then
		io.stdout:write(data)
		-- break
	end
end
client:write("hello world")
