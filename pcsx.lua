--[[
    PCSX2-Redux Script
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
	local output_str = string.format("[LOG] enter CdReadSector,read %s sector,to 0x%X,starts with No. %s sector",U(counter_sector),buffer_addr,U(sector_number));
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


	local output_str = string.format("[LOG] enter CdAsyncSeekL with 0x%X",final_value);
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
	    local output_str = string.format("[TRACE] -> possible stack: 0x%X",final_value);
	    print(output_str)
	end
	initial_offset += 4;
    end
    print("done")
end


--[[
    PS1读取XA-ADPCM有两种方法 一种是通过sound map,第二种就是直接read然后丢给SPU
    我们需要给几个地方下装 1. CHPCTL寄存器 2. paramter 3. command 4. DMA Controller(channel 3)并且检查是否开启DMA channel 3使能位,DMA channel 3
    同时对CHPCTL做一个ADPCM位检查(WRDATA,SMEN) 因为我认为PS1的系统同理 就像在在写入了Read命令 收到中断后后必须设置BFRD 才开始写入一样 我认为WRDATA只有打开 这个位才会认
    我们还需要检测游戏用的是否是sound map ADPCM
]]--
--cd_rom_cur_state = 0;
--cd_rom_is_pio = true;
local bit = require("bit")
local bit32 = {}

-- bit32.extract(n, field, width)
-- 等价于取 n 的第 field 位开始、共 width 位，field 从 0 开始
function bit32.extract(n, field, width)
    width = width or 1
    local mask = bit.lshift(1, width) - 1
    return bit.band(bit.rshift(n, field), mask)
end

function handle_command(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile() --为什么IO空间地址的读写并没有提供??
    --尝试检查 DMA Control register的CDROM使能位
    f:rSeek(0x1f801801);
    data = f:read(1);
    if data then
        alias_suffix = ""
        if data[0] == 0x01 then
            alias_suffix = alias_suffix .. "(NOP)"
        elseif data[0] == 0x02 then
            alias_suffix = alias_suffix .. "(Setloc)"
        elseif data[0] == 0x03 then
            alias_suffix = alias_suffix .. "(Play)"
        elseif data[0] == 0x06 then
            alias_suffix = alias_suffix .. "(ReadN)"
        elseif data[0] == 0x15 then
            alias_suffix = alias_suffix .. "(SeekL)"
        elseif data[0] == 0x16 then
            alias_suffix = alias_suffix .. "(SeekP)"
        elseif data[0] == 0x1b then
            alias_suffix = alias_suffix .. "(ReadS)"
        end
        output_str = string.format("[CDROM] write command 0x%x" .. alias_suffix, data[0]);
        print(output_str);
    else
        print("read out NIL!")
    end
    PCSX.resumeEmulator();
end

--0x1f801802    通过多次写 会清空 bank0.ADDRESS.PRMWRDY 可能BIOS需要初始等PRMEMPT 然后再写到PRMWRDY 然后写CLR寄存器
--先parameter还是先command? COMMAND写会drain the parameter FIFO注意 所以是command后parameter
function handle_parameter(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile()
    f:rSeek(0x1f801802);
    data = f:read(1);
    print("[LOG] write Parameter with " .. tostring(tonumber(data[0])));
    PCSX.resumeEmulator();
end

--0x1f801803 write
function handle_hchpctl(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile()
    local output_str = ""
    f:rSeek(0x1f801803);
    data = f:read(1);
    local mask = bit32.extract(data[0],5,3);
    if mask == 0 then
        --output_str = "NITHER enalbed!" .. tostring(tonumber(mask))
	print("IGNOREME")
	PCSX.resumeEmulator();
	return true;
    elseif mask == 1 then
        output_str = "Sound Map enabled"
    elseif mask == 2 then
        output_str = "a read request"
    elseif mask == 4 then
        output_str = "a write request"
    end
    print("[CDROM] write HCHPCTL with " .. output_str);
    PCSX.resumeEmulator();
end

--write trigger 1F8010B8h DMA Channel Control
function handle_cdrom_dma(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator(); --等待CPU写入
    local f = PCSX.getMemoryAsFile()
    local output_string = "[DMA-CDROM] "
    --read DMA base address (Channel 0..6)
    f:rSeek(0x1F8010B0);
    data = f:read(4);
    local dest_ram = data[0] + 0x100 * data[1] + 0x10000 * data[2] + 0x1000000 * data[3];
    output_string = output_string .. string.format("dest ram: 0x%X", dest_ram);
    --read  DMA Block Control (Channel 0..6) (R/W)
    f:rSeek(0x1F8010B4);
    data = f:read(2);
    local byte_amount = data[0] + 0x100 * data[1];
    output_string = output_string .. string.format(" ,read %d bytes", byte_amount);
    
    f:rSeek(0x1F8010B8);
    data = f:read(4); --4字节 注意! 返回的是Buffer!!
    --data[0] = first byte!!

    local transfer_mode = 0;
    local is_start = 0;
    transfer_mode = transfer_mode + tonumber(bit32.extract(data[1],1,2)); --1,2位 0计数的
    is_start = tonumber(bit32.extract(data[3],1,1));
--  if(is_start == 1) then
--      output_string = output_string .. " ,starting";
--  else
--  end
    
    local dir = tonumber(bit32.extract(data[0],0,1));
    if(dir == 1) then
        output_string = output_string .. " ,RAM to Device!";
    else
        output_string = output_string .. " ,Device to RAM!";
    end
    print(output_string);
    PCSX.resumeEmulator();
    return true;
end



--2 byte
function handle_spu_sample(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile()
    f:rSeek(tonumber(address));
    local data = f:read(2);
    local ram_not_mul = data[0] + 0x100 * data[1];
    local ram_addr = ram_not_mul * 8;
    print(string.format("[SPU-SAMPLE-PLAY] write 0x%X(!!SPU ram!!) to 0x%X: ", tonumber(ram_addr), tonumber(address)))
    PCSX.resumeEmulator();
end

--2 byte set SPU internal bus target addr for DMA
function handle_spu_mem(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile()
    f:rSeek(tonumber(address));
    local data = f:read(2);
    local ram_not_mul = data[0] + 0x100 * data[1];
    local ram_addr = ram_not_mul * 8;
    print(string.format("[SPU-MEM] DMA purpose, write 0x%X(!!SPU ram!!) to 0x%X: ", tonumber(ram_addr), tonumber(address)))
    PCSX.resumeEmulator();
end

--1F8010Cxh
function handle_spu_dma(address,width,cause)
    PCSX.resumeEmulator();
    PCSX.pauseEmulator();
    local f = PCSX.getMemoryAsFile();

    f:rSeek(0x1F8010C0);
    local addr_data = f:read(4);
    local addr = addr_data[0] + addr_data[1]*0x100 + addr_data[2]*0x10000 + addr_data[3]*0x1000000;

    f:rSeek(0x1F8010C4);
    local ctrl_data = f:read(4);
    local block_size = ctrl_data[0] + ctrl_data[1]*0x100;
    local block_amount = ctrl_data[2] + ctrl_data[3]*0x100;

    f:rSeek(0x1F8010C8);
    local info = f:read(4);
    local dir = bit32.extract(info[0], 0, 1);
    if dir == 0 then
        dir = ",device to ram"
    else
        dir = ",ram to device"
    end

    local is_start = bit32.extract(info[3], 0, 1);  -- CHCR bit 24
    --if is_start == 1 then
    if true then
        local final_str = "[DMA-SPU] rw from addr(CPU bus) " .. string.format("0x%X", addr) ..
                          " with " .. tostring(block_size) .. " words per block, with " ..
                          tostring(block_amount) .. dir
        print(final_str)
    end
    
    PCSX.resumeEmulator();
end

DUMP_PATH = "/tmp/mem.dmp"

function dump_memory(addr, size)
    os.remove(DUMP_PATH)          -- 每次先删旧文件

    local mem = PCSX.getMemPtr()
    if not mem then
        print("getMemPtr() failed")
        return
    end

    local f = io.open(DUMP_PATH, "wb")
    if not f then
        print("cannot open " .. DUMP_PATH)
        return
    end

    -- C 指针：mem[addr] 就是 addr 处的字节，不需要 +1
    for i = 0, size - 1 do
        local b = mem[addr + i]
        if b < 0 then b = b + 256 end   -- cdata int8 符号扩展修正
        f:write(string.char(b))
    end

    f:close()
    print(string.format("dumped %d bytes @ 0x%08X -> %s", size, addr, DUMP_PATH))
end
print("正在添加...")

br = PCSX.addBreakpoint(0x1f801801, "Write", 1, "trap in bank 0 COMMAND", handle_command);
br:enable();

br_param = PCSX.addBreakpoint(0x1f801802, "Write", 1, "trap in bank 0 PARAMETER", handle_parameter);
br_param:enable();

br_hchpctl = PCSX.addBreakpoint(0x1f801803, "Write", 1, "trap in bank 0 HCHPCTL", handle_hchpctl);
br_hchpctl:enable();

br_dma = PCSX.addBreakpoint(0x1F8010B8, "Write", 4, "trap DMA channel 3 CHCR", handle_cdrom_dma);
br_dma:enable();

br_vc1 = PCSX.addBreakpoint(0x1F801C0E, "Write", 2, "SPU LSAX voice 0", handle_spu_sample);
br_vc1:enable();

br_vc2 = PCSX.addBreakpoint(0x1F801C1E, "Write", 2, "SPU LSAX voice 1", handle_spu_sample);
br_vc2:enable();

br_spumem = PCSX.addBreakpoint(0x1f801da6, "Write", 2, "SPU transfer address", handle_spu_mem);
br_spumem:enable();

br_spudma = PCSX.addBreakpoint(0x1F8010C8, "Write", 4, "SPU DMA CHCR", handle_spu_dma);
br_spudma:enable();

print("添加成功")
