#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>
# define max_syscall 20
# define USER_VADDR_BOUND (void*) 0x08048000

static void (*syscalls[max_syscall])(struct intr_frame *);
/* Our implementation for Task2: syscall halt,exec,wait and practice */
void sys_halt(struct intr_frame* f); /* syscall halt. */
void sys_exit(struct intr_frame* f); /* syscall exit. */
void sys_exec(struct intr_frame* f); /* syscall exec. */

/* Our implementation for Task3: syscall create, remove, open, filesize, read, write, seek, tell, and close */
// void sys_create(struct intr_frame* f); /* syscall create */
// void sys_remove(struct intr_frame* f); /* syscall remove */
// void sys_open(struct intr_frame* f);/* syscall open */
void sys_wait(struct intr_frame* f); /*syscall wait */
// void sys_filesize(struct intr_frame* f);/* syscall filesize */
// void sys_read(struct intr_frame* f);  /* syscall read */
void sys_write(struct intr_frame* f); /* syscall write */
// void sys_seek(struct intr_frame* f); /* syscall seek */
// void sys_tell(struct intr_frame* f); /* syscall tell */
// void sys_close(struct intr_frame* f); /* syscall close */

static void syscall_handler (struct intr_frame *);
struct thread_file * find_file_id(int fd);


void 
exit_special (void)
{
  thread_current()->exit_status = -1;
  thread_exit ();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /* Our implementation for Task2: initialize halt,exit,exec */
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
  
  //   // /* Our implementation for Task3: initialize create, remove, open, filesize, read, write, seek, tell, and close */
  syscalls[SYS_WAIT] = &sys_wait;
  // syscalls[SYS_CREATE] = &sys_create;
  // syscalls[SYS_REMOVE] = &sys_remove;
  // syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  // syscalls[SYS_SEEK] = &sys_seek;
  // syscalls[SYS_TELL] = &sys_tell;
  // syscalls[SYS_CLOSE] =&sys_close;
  // syscalls[SYS_READ] = &sys_read;
  // syscalls[SYS_FILESIZE] = &sys_filesize;
}

static int 
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}
/* New method to check the address and pages to pass test sc-bad-boundary2, execute */
void * 
check_ptr2(const void *vaddr)
{ 
  /* Judge address */
  if (!is_user_vaddr(vaddr))
  {
    exit_special ();
  }
  /* Judge the page */
  void *ptr = pagedir_get_page (thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    exit_special ();
  }
  /* Judge the content of page */
  uint8_t *check_byteptr = (uint8_t *) vaddr;
  for (uint8_t i = 0; i < 4; i++) 
  {
    if (get_user(check_byteptr + i) == -1)
    {
      exit_special ();
    }
  }

  return ptr;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  /* For Task2 practice, just add 1 to its first argument, and print its result */
  int * p = f->esp;
  check_ptr2 (p + 1);
  int type = * (int *)f->esp;
  if(type <= 0 || type >= max_syscall){
    exit_special ();
  }
  syscalls[type](f);
}


/* Method in document to handle special situation */
/* 在用户虚拟地址 UADDR 读取一个字节。
   UADDR 必须低于 PHYS_BASE。
   如果成功则返回字节值，如果
   发生段错误则返回 -1 。*/ 

void 
sys_halt (struct intr_frame* f)
{
  shutdown_power_off();
}


void 
sys_exit (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  *user_ptr++;
  /* record the exit status of the process */
  thread_current()->exit_status = *user_ptr;
  thread_exit ();
}


void 
sys_exec (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  check_ptr2 (*(user_ptr + 1));
  *user_ptr++;
  f->eax = process_execute((char*)* user_ptr);
}

void 
sys_wait (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

struct thread_file * 
find_file_id (int file_id)
{
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    if (file_id == thread_file_temp->fd)
      return thread_file_temp;
  }
  return false;
}


void 
sys_write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 7);
  check_ptr2 (*(user_ptr + 6));
  *user_ptr++;
  int temp2 = *user_ptr;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (temp2 == 1) {
    /* Use putbuf to do testing */
    putbuf(buffer,size);
    f->eax = size;
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f ();
    } 
    else
    {
      f->eax = 0;
    }
  }
}