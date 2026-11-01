--[[
    Omnipresence.....
]]--


local function U(v)
    v = tonumber(v) or 0
    if v < 0 then
	v = v + 0x100000000
    end
    return tostring(v)
end


local read_handler = function(param1,param2,param3,param4)
    --param1 only
    --note: 我需要声明的是 R300A针对 0x80000000以上地址访问实际上通过固定的规律映射到物理内存 反正我拦截看到这两个混用 所以加一个guard 来适用PCSX.getMemPtr();
    local p = param1;
    if p >= 0x80000000 then
	p = p - 0x80000000;
    end
    local guest_mem = PCSX.getMemPtr();
    local initial_char_idx = 0;
    local file_name_str = "";
    while initial_char_idx < 100 do
	local cur_char = string.char(tonumber(guest_mem[p + initial_char_idx]));
	file_name_str = file_name_str .. cur_char;
	if cur_char == "\0" then
	    break;
	end
	initial_char_idx = initial_char_idx + 1;
    end
    local output_str = string.format("[LOG] enter open for %s",file_name_str);
    print(output_str);
end;

custom_a0_table = {
    [0x00] = read_handler,
    [0xA4] = function(param1,param2,param3,param4)
	--param1 == dest
	local p = param1;
	if p >= 0x80000000 then
	    p = p - 0x80000000;
	end
	local guest_mem = PCSX.getMemPtr();
	local initial_char_idx = 0;
	local file_name_str = "";
	while initial_char_idx < 100 do
	    local cur_char = string.char(tonumber(guest_mem[p + initial_char_idx]));
	    file_name_str = file_name_str .. cur_char;
	    if cur_char == "\0" then
 		break;
 	    end
	    initial_char_idx = initial_char_idx + 1;
	end
	local output_str = string.format("[LOG] enter CdGetLbn for %s",file_name_str);
	print(output_str)
    end,
    [0xA5] = function(param1,param2,param3,param4)
	local counter_sector = param1;
	local sector_number = param2;
	local buffer_addr = param3;
	local output_str = string.format("[LOG] enter CdReadSector,read %s sector,to %X,starts with No. %s sector",U(counter_sector),buffer_addr,U(sector_number));
	print(output_str)
    end,
    [0x78] = function(param1,param2,param3,param4) --CdAsyncSeekL
	local src_addr = param1;
	if src_addr >= 0x80000000 then
	    src_addr = src_addr - 0x80000000;
	end
	local guest_mem = PCSX.getMemPtr();
	local b0 = guest_mem[src_addr+0];
	local b1 = guest_mem[src_addr+1];
	local b2 = guest_mem[src_addr+2];
	--00_expected lower bit for lower addr byte!
	local final_value = 0x00000000;

	final_value = final_value + b0;
	final_value = final_value + (0x100 * b1);
	final_value = final_value + (0x10000 * b2);
--	final_value = final_value + b2;
--	final_value = (final_value << 8);
--	final_value = final_value + b1;
--	final_value = (final_value << 8);
--	final_value = final_value + b0;


	local output_str = string.format("[LOG] enter CdAsyncSeekL with %X",final_value);
	print(output_str);
    end,
    [0x7E] = function(param1,param2,param3,param4)
	local counter_sector = param1;
	local buffer_addr = param2;
	local mode = param3;
	local output_str = string.format("[LOG] enter CdAsyncReadSector,read %s sector,to %X, with mode %X,starts with last CdSeek",U(counter_sector),buffer_addr,mode);
	print(output_str)
    end

}
custom_b0_table = {
    [0x08] = function(param1,param2,param3,param4)
--	class spec mode func
	local output_str = string.format("[LOG] enter OpenEvent tracer where class is %X, specs is %X, modes is %X, addr of func is %X",param1,param2,param3,param4)
--	print(output_str)
    end,
    [0x32] = read_handler
}
custom_a0_handler = function(address,width,cause)
    local gprs = PCSX.getRegisters().GPR.n;
    local func_code = gprs.t1;
    local param1 = gprs.a0;
    local param2 = gprs.a1;
    local param3 = gprs.a2;
    local param4 = gprs.a3;
    if custom_a0_table[func_code] then
	local func = custom_a0_table[func_code]
	func(param1,param2,param3,param4);
    end
    PCSX.resumeEmulator();
    return true;
end

custom_b0_handler = function(address,width,cause)
    local gprs = PCSX.getRegisters().GPR.n;
    local func_code = gprs.t1;
    local param1 = gprs.a0;
    local param2 = gprs.a1;
    local param3 = gprs.a2;
    local param4 = gprs.a3;
    if custom_b0_table[func_code] then
	local func = custom_b0_table[func_code]
	func(param1,param2,param3,param4);
    end
    PCSX.resumeEmulator();
    return true;
end
function try_trace()
    PCSX.pauseEmulator();
    local gprs = PCSX.getRegisters().GPR.n;
    local guest_mem = PCSX.getMemPtr();
    local init_sp = 0x001FFF00; --这个模拟器好像不听PE而是CNF的 不过无伤大雅
    local cur_sp = gprs.sp;
    if(cur_sp >= 0x80000000) then
	cur_sp -= 0x80000000; --转换虚拟地址到物理地址
    end
    --initial SP: 0x801fff00,offset 0x0,
    --initial RAM,0x80010000,0x00096800
    --possible range of whole EXE in RAM [0x80010000,0x800A6800)
    --R300A little-endian!
    local initial_offset = 0;
    while true do
	if (tonumber(cur_sp)+initial_offset+3) >= 0x00010000 and
	(tonumber(cur_sp)+initial_offset+3) < 0x000A6800 then
	    print("!!overflowed!!")
	    break;
	end
	if cur_sp+initial_offset >= init_sp then
	    print("reached edge,exit")
	    break;
	end
	--对于上一个越界也没有毛病 至少不影响 至少来说栈是需要对齐的 我想当初Sony SDK的开发者也知道
	local b0 = guest_mem[tonumber(cur_sp)+initial_offset+0]
	local b1 = guest_mem[tonumber(cur_sp)+initial_offset+1]
	local b2 = guest_mem[tonumber(cur_sp)+initial_offset+2]
	local b3 = guest_mem[tonumber(cur_sp)+initial_offset+3]
	local final_value = 0x00000000; --00_expected lower bit for lower addr byte!

	final_value = final_value + (b1 * 0x100);
	final_value = final_value + (b2 * 0x10000);
	final_value = final_value + (b3 * 0x1000000);
	final_value = final_value + b0;

	if(final_value >= 0x80010000 and
	   final_value < 0x800A6800) then
	    local output_str = string.format("[TRACE] -> possible stack: %X",final_value);
	    print(output_str)
	end
	initial_offset += 4;
    end
    print("done")
end
print("正在添加...")
A0_br = PCSX.addBreakpoint(0xA0,"Exec",4,"trap in A0",custom_a0_handler);
B0_br = PCSX.addBreakpoint(0xB0,"Exec",4,"trap in B0",custom_b0_handler);
print("添加成功")
