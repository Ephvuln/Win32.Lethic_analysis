# Code referes function from: github.com/Bluelive/unpack-ta505packer-qiling
# Will be called as ref.
from capstone import *
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import * 



# Optimized form ref, big memory chunk can cause qiling 
# to kill the process due to not responding
def dump_parts(ql,start,stop):
    size = 1000
    print( "Dump memory region at address: {} - : {}".format(hex(start), hex(stop)))
    s = start
    with open("unpacked_"+hex(start)+"-"+hex(stop)+".bin", "wb") as f:

        while True:
            excuted_mem = ql.mem.read(s, size)
            f.write(excuted_mem) 
            
            if s >=stop:
                break
            else:
                s = (s +size)%stop

        print("MemDump finished")


# adapted from ref
@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_HeapFree(ql, address, params):
    lpAddress = params["lpMem"]
    print("HeapFree called for address: {}".format(hex(lpAddress)))
    ql.os.heap.free(lpAddress)

    return 1

@winsdkapi(cc=STDCALL, dllname="msvcrt_dll")
def hook___wgetmainargs(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_GetConsoleMode(ql, address, params):
    ret = 0
    params['lpmode']= 0x277

    return ret


# adapted from ref
def _WriteFile(ql: Qiling, address: int, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    #lpOverlapped = params["lpOverlapped"]


    f = ql.os.handle_manager.get(hFile)

    if f is None:
        # Invalid handle
        ql.os.last_error = 0xffffffff
        return 0
    else:
        f = f.obj

    buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
    print("Program wrote: ",buffer)
    if f != None:
        f.write(bytes(buffer))
        ql.mem.write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
    return ret

@winsdkapi(cc=STDCALL, dllname='kernel32_dll', replace_params={
    "hFile": HANDLE,
    "lpBuffer": POINTER,
    "nNumberOfBytesToWrite": DWORD,
    "lpNumberOfBytesWritten": POINTER,
    "lpOverlapped": POINTER
})
def hook_WriteFile(ql: Qiling, address: int, params):
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    
    return _WriteFile(ql, address, params)


@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def hook_VirtualLock(ql: Qiling, address: int, params):
    return 1


once = 0



@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def hook_HeapAlloc(ql, address, params):


    ret = ql.os.heap.alloc(params["dwBytes"])

    return ret


# adapted from ref
def patch_binary(ql):  

    patches = [] 

    # Patch the HeapAlloc loop to not execute.
    patch_ = { 
        'original': b'\x83\xbd\x64\xde\xff\xff\x37', 
        'patch': b'\x83\xbd\x64\xde\xff\xff\x00' 
    } 

    patches.append(patch_) 
  
    for patch in patches:  
        antiemu_loop_addr = ql.mem.search(patch['original']) 
        if antiemu_loop_addr: 
            print( 'Found Anti-Emulation loop at addr: {}'.format(hex(antiemu_loop_addr[0])))  
            try: 
                ql.patch(antiemu_loop_addr[0], patch['patch']) 
                print( 'Successfully patched!') 
                return 
            except Exception as err: 
                print( 'Unable to patch binary: {}'.format(err))
#



@winsdkapi(cc=STDCALL, dllname='user32_dll')
def hook_GetProcessWindowStation(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, dllname='user32_dll')
def hook_MessageBoxW(ql, address, params):
    return 1

# Expected before injection into explorer.exe
@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def hook_CreateThread(ql, address, params):
    print(params)
    ql.emu_stop()
    return -1


@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def hook_GetSystemTime(ql, address, params):
    ### Dose not trigger
    params['lpSystemTime']=1


start_printing = False

def print_asm(ql, address, size):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    buf = ql.mem.read(address, size)


    global start_printing

    if(buf == b')\xd0'):
        print("Found Anti-Emulation Sleep. Hacking registers..")
        ql.reg.eax=ql.reg.edx

    if(buf ==b'f;\x9d@\xfd\xff\xff'):
        start_printing = True

    for i in md.disasm(buf, address):
        if(start_printing):
            print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        if i.address ==  0xffff31f1:
            print("Found Anti-Emulation loop1. Hacking outside loop.")
            ql.reg.edx=0
            ql.reg.eip = 0xffff31f1+3+2 #Bingo


        if i.address ==  0xffff3566:
            print("Found Anti-Emulation loop2. Hacking..")
            print("Expected BX to equal [",hex(ql.reg.ebp),"+0xfffffd40]=",ql.mem.read(0xffff2d44, 2)) # 0xffff3004 + 0xfffffd40 = 0xffff2d44
            ql.reg.bx = 0


        if i.address == 0xffff3584:
            print("EBP ====== ",ql.reg.ebp)

        if i.address == 0xffff359d: # Invalid memory read.
            print("Emulating guess of LoadResourceA")
            ql.reg.esp = ql.reg.esp -3*4
            ql.reg.eip = ql.reg.eip+3 # instruction length
            ql.reg.eax=0xffff2ee6
            #print("dword ptr [ebp - 0x10] = [", hex(ql.reg.ebp - 0x10),"] = ",[ hex(j) for j in ql.mem.read(ql.reg.ebp - 0x10,4)] )
            #print(ql.mem.show_mapinfo())

        if i.address == 0xffff35c6:
            ql.reg.eip +=2

        '''
        if i.address == 0xffff3728:
            dump_parts(ql,0x05004000, 0x5005000)
            dump_parts(ql,0x05005000, 0x5007000)
            dump_parts(ql,0xfffdd000, 0xffffe000)
        '''



@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def hook_FindResourceA(ql, address, params):
    print(params)
    return 0


def sandbox():

    # create a sandbox for Windows x86
    ql = Qiling(['rootfs/x86_windows/bin/lephic.bin'],"rootfs/x86_windows",QL_VERBOSE.DEBUG)

    try:

        ql.set_api("HeapFree", hook_HeapFree)

        ql.set_api("GetConsoleMode", hook_GetConsoleMode)
        ql.set_api("WriteFile", hook_WriteFile)
        ql.set_api("VirtualLock", hook_VirtualLock)
        ql.set_api("HeapAlloc", hook_HeapAlloc)
        ql.set_api("CreateThread", hook_CreateThread)

        ql.set_api("GetProcessWindowStation", hook_GetProcessWindowStation)
        ql.set_api("MessageBoxW", hook_MessageBoxW)
        ql.set_api("GetSystemTime", hook_GetSystemTime)
        ql.set_api("FindResourceA", hook_FindResourceA)
        
        ql.hook_code(print_asm)

        patch_binary(ql)

        ql.run()

    except Exception as err:
        print('An error occurred with Qiling Framework: {}'.format(err))



if __name__ == "__main__":
    
    print("Started")

    sandbox()

    print("Finished")
