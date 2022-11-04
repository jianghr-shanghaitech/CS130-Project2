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
# define USER_VADDR_BOUND (void*) 0x08048000
static void (*syscalls[15])(struct intr_frame *);

/* Our implementation for Task2: syscall halt,exec,wait and practice */
void halt(); /* syscall halt. */
void exit(int status); /* syscall exit. */
void exec(struct intr_frame* f); /* syscall exec. */

/* Our implementation for Task3: syscall create, remove, open, filesize, read, write, seek, tell, and close */
void create(struct intr_frame* f); /* syscall create */
void remove(struct intr_frame* f); /* syscall remove */
void open(struct intr_frame* f);/* syscall open */
void wait(struct intr_frame* f); /*syscall wait */
void filesize(struct intr_frame* f);/* syscall filesize */
void read(struct intr_frame* f);  /* syscall read */
void write(struct intr_frame* f); /* syscall write */
void seek(struct intr_frame* f); /* syscall seek */
void tell(struct intr_frame* f); /* syscall tell */
void close(struct intr_frame* f); /* syscall close */
static void syscall_handler (struct intr_frame *);
struct thread_file * find_file_id(int fd);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static int 
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

void * ptr2(const void *vaddr)
{ 
  if (!is_user_vaddr(vaddr) || (!pagedir_get_page (thread_current()->pagedir, vaddr)))
  {
    thread_current()->exit_status = -1;
    thread_exit ();
  }
  uint8_t *check_byteptr = (uint8_t *) vaddr;
  uint8_t i = 0;
  while (i < 4) 
  {
    if (get_user(check_byteptr + i) == -1)
    {
      thread_current()->exit_status = -1;
      thread_exit ();
    }
    i++;
  }
  return pagedir_get_page (thread_current()->pagedir, vaddr);
}


void 
halt ()
{
  // Terminates Pintos
  shutdown_power_off();
}

void 
exit (int status)
{
  thread_current()->exit_status = status;
  // Terminates the current user program
  thread_exit ();
}

/* Do sytem exec */
void 
exec (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  ptr2 (*(user_ptr + 1));
  *user_ptr++;
  f->eax = process_execute((char*)* user_ptr);
}

/* Do sytem wait */
void 
wait (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

/*Our implementation for Task3: create, remove, open, filesize, read, write, seek, tell, and close */

/* Do sytem create, we need to acquire lock for file operation in the following methods when do file operation */
void 
create(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 5);
  ptr2 (*(user_ptr + 4));
  *user_ptr++;
  acquire_lock_f ();
  f->eax = filesys_create ((const char *)*user_ptr, *(user_ptr+1));
  release_lock_f ();
}

/* Do system remove, by calling the method filesys_remove */
void 
remove(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  ptr2 (*(user_ptr + 1));
  *user_ptr++;
  acquire_lock_f ();
  f->eax = filesys_remove ((const char *)*user_ptr);
  release_lock_f ();
}

/* Do system open, open file by the function filesys_open */
void 
open (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  ptr2 (*(user_ptr + 1));
  *user_ptr++;
  acquire_lock_f ();
  struct file * file_opened = filesys_open((const char *)*user_ptr);
  release_lock_f ();
  struct thread * t = thread_current();
  if (file_opened)
  {
    struct thread_file *thread_file_temp = malloc(sizeof(struct thread_file));
    thread_file_temp->fd = t->file_fd++;
    thread_file_temp->file = file_opened;
    list_push_back (&t->files, &thread_file_temp->file_elem);
    f->eax = thread_file_temp->fd;
  } 
  else
  {
    f->eax = -1;
  }
}
/* Do system write, Do writing in stdout and write in files */
void 
write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 7);
  ptr2 (*(user_ptr + 6));
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
/* Do system seek, by calling the function file_seek() in filesystem */
void 
seek(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 5);
  *user_ptr++;
  struct thread_file *file_temp = find_file_id (*user_ptr);
  if (file_temp)
  {
    acquire_lock_f ();
    file_seek (file_temp->file, *(user_ptr+1));
    release_lock_f ();
  }
}

/* Do system tell, by calling the function file_tell() in filesystem */
void 
tell (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file *thread_file_temp = find_file_id (*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f ();
    f->eax = file_tell (thread_file_temp->file);
    release_lock_f ();
  }else{
    f->eax = -1;
  }
}

/* Do system close, by calling the function file_close() in filesystem */
void 
close (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file * opened_file = find_file_id (*user_ptr);
  if (opened_file)
  {
    acquire_lock_f ();
    file_close (opened_file->file);
    release_lock_f ();
    /* Remove the opened file from the list */
    list_remove (&opened_file->file_elem);
    /* Free opened files */
    free (opened_file);
  }
}
/* Do system filesize, by calling the function file_length() in filesystem */
void 
filesize (struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file * thread_file_temp = find_file_id (*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f ();
    f->eax = file_length (thread_file_temp->file);
    release_lock_f ();
  } 
  else
  {
    f->eax = -1;
  }
}

/* Check is the user pointer is valid */
bool 
is_valid_pointer (void* esp,uint8_t argc){
  for (uint8_t i = 0; i < argc; ++i)
  {
    if((!is_user_vaddr (esp)) || 
      (pagedir_get_page (thread_current()->pagedir, esp)==NULL)){
      return false;
    }
  }
  return true;
}


/* Do system read, by calling the function file_tell() in filesystem */
void 
read (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  /* PASS the test bad read */
  *user_ptr++;
  /* We don't konw how to fix the bug, just check the pointer */
  int fd = *user_ptr;
  int i;
  uint8_t * buffer = (uint8_t*)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (!is_valid_pointer (buffer, 1) || !is_valid_pointer (buffer + size,1)){
      thread_current()->exit_status = -1;
  thread_exit ();
  }
  /* get the files buffer */
  if (fd == 0) 
  {
    for (i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  }
  else
  {
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();
      f->eax = file_read (thread_file_temp->file, buffer, size);
      release_lock_f ();
    } 
    else
    {
      f->eax = -1;
    }
  }
}

/* Find file by the file's ID */
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

/* Smplify the code to maintain the code more efficiently */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  /* For Task2 practice, just add 1 to its first argument, and print its result */
  int * p = f->esp;
  check_ptr2 (p + 1);
  switch(*(int *)f->esp){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(f->esp + 1);
      break;
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
    default:
      exit_special ();
      break;
  }
  // int type = * (int *)f->esp;
  // if(type <= 0 || type >= max_syscall){
  //   exit_special ();
  // }
  // syscalls[type](f);
}
