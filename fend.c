#include <sys/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <pwd.h>

char *fileToExecute;
char buf[PATH_MAX]; 
char *configFile;
int status;
int numberOfLines = 0;
 FILE *fptr;

struct configFileContents
{
    char *permission;
	char *filename;
    struct configFileContents *next;

};

 

struct configFileContents *head = NULL;
struct configFileContents *temp = NULL;
char *line;




void handleConfigFile()
{
   
    if(strcmp(configFile,".fendrc") != 0)
    {
        fptr = fopen(configFile,"r");
    }
    else
    {
        struct stat buffer;
        int exist = stat(configFile,&buffer);
        
        if(exist == 0)
        {
            fptr = fopen(configFile,"r");
        }
        else
        {
            uid_t uid = getuid();
            char *slash = "/";
            struct passwd *pw = getpwuid(uid);
            char *new_string = malloc(PATH_MAX);
            new_string = '\0';
            strcat(new_string,pw->pw_dir);
            strcat(new_string,slash);
            strcat(new_string,configFile);

            fptr = fopen(new_string,"r");
            if(fptr == NULL)
            {
                printf("Must provide a Valid config file\n");
                exit(0);
            }
 
        }
    }
    if(fptr == NULL)
    {
        printf("Must provide a config file\n");
        exit(0);
    }


}

void sandbox_kill(pid_t pid) 
{
	printf(":Permission denied\n");
    
	kill(pid, SIGKILL);

	wait(NULL);
   
   
	exit(EACCES);
}

char* verifyConfigFile(char * fileNameToMatch)
{
     size_t len;

     char *permissionToConsider = NULL;
     

     while ((getline(&line, &len, fptr)) != -1) 
     {


		char * filePermission = strtok(line, " \t\n");

 

		char * fileName = strtok(NULL, " \t\n");
		
            
         if(fnmatch(fileName,fileNameToMatch, FNM_PATHNAME) == 0)
         {
            
             permissionToConsider = filePermission;
          
         }

       
	}

   
    rewind(fptr);  

    return permissionToConsider;    
}

 // The code to read the strings in registers is taken from this github code - https://github.com/nelhage/ministrace/blob/master/ministrace.c
char *read_string(pid_t child, unsigned long long int addr) {
	char *val = malloc(4096);
	int allocated = 4096;
	int read = 0;
	unsigned long tmp;
	while (1) {
		if (read + sizeof tmp > allocated) {
			allocated *= 2;
			val = realloc(val, allocated);
		}
		tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
		if (errno != 0) {
			val[read] = 0;
			break;
		}
		memcpy(val + read, &tmp, sizeof tmp);
		if (memchr(&tmp, 0, sizeof tmp) != NULL)
			break;
		read += sizeof tmp;
	}
	return val;
}


void handleSystemcall(pid_t pid, char *argv[])
{
    struct user_regs_struct regs;
    int permissionRequired;


    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "Failed to PTRACE_GETREGS:");

     //   printf("   *****  %lld   ****", regs.orig_rax);

    char *fileName;

    if(regs.orig_rax == 257 || regs.orig_rax == 2)
    {

    

 
     if(regs.orig_rax == 257)
    {
        
        char *registerString = read_string(pid,regs.rsi);

      

      //   fileName =  registerString;


        fileName = realpath(registerString, buf);

      //  printf("\n  ****  FILENAME =>   %s\n", fileName);
        
        permissionRequired = (regs.rdx & O_ACCMODE);

       
    }
    else if(regs.orig_rax == 2)
    {
       
        fileName = read_string(pid,regs.rdi);

     //   printf("\n  ****  1 %s\n", fileName);


        permissionRequired = (regs.rsi & O_ACCMODE);
    }

   
     
    char *permissionToConsider = verifyConfigFile(fileName);

  //   printf("\n  ****  PermissionToConsider %s\n", permissionToConsider);

     if(permissionToConsider != NULL)
     {
         if(permissionRequired == O_RDONLY)
         {
           
             if(permissionToConsider[0] == '0')
             {
                
                sandbox_kill(pid);
             }
         }
         else if(permissionRequired == O_WRONLY)
         {
           
             if(permissionToConsider[1] == '0')
             {
                 sandbox_kill(pid);
             }
         }
         else if(permissionRequired == O_RDWR)
         {
          
             if (!(permissionToConsider[1] == '1' && permissionToConsider[0] == '1'))
             {
                 sandbox_kill(pid);
             }
         }
     }
     }

}

void sandbox_run(pid_t pid, char *argv[])
{
    struct user_regs_struct regs;    

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "Failed to PTRACE_GETREGS:");

       

    if(regs.orig_rax == 59)  // execve system call
    {
        if(fileToExecute != NULL)
        {
            char *permissionToConsider = verifyConfigFile(fileToExecute);
     

        if(permissionToConsider != NULL)
        {
            if(permissionToConsider[2]=='0')
            {
                sandbox_kill(pid);
            }
        }    

        }
          
    }

   

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) 
    {	
        printf("Error in PTRACE_SYSCALL. ");
        sandbox_kill(pid);
        exit(0);        
	}
    wait(&status);

    if (WIFEXITED(status)) {
		exit(EXIT_SUCCESS);
	}

    if (WIFSTOPPED(status)) {
		handleSystemcall(pid, argv);
	}
}

int main(int argc, char *argv[])
{   

    if(argc ==1)
    {
        printf("Too few arguements. \n");
        exit(0);
    }
    if(argc == 2)
    {
        printf("Too few arguements. \n");
    }
    else if(argc ==2)
    {
        if(strcmp("-c", argv[1]) != 0)
        {
            fileToExecute = realpath(argv[1], buf);
        }
        else
        {
            printf("\n Must provide a config file");
        }
    }  



    if(strcmp("-c", argv[1]) == 0)
    {
        configFile = argv[2]; 
        if(argc == 4)
        {
            fileToExecute = realpath(argv[3], buf);
        }
        else
        {
            argv = argv + 3;
			argc = argc - 3;
        }

        handleConfigFile();        
    }
    else
    {
       
        configFile = ".fendrc";
        argv = argv + 3;
		argc = argc - 3;

        handleConfigFile();
    }

    pid_t pid = fork();

   if(pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      err(EXIT_FAILURE, "Failed to PTRACE_TRACEME");
    }

    execvp(argv[0], argv);
    err(EXIT_FAILURE, "Failed to execv %s", argv[0]);
  } 
  else 
  {
    wait(NULL);
  }

  for(;;)
  {
      sandbox_run(pid,argv);
  }
  
  exit(EXIT_SUCCESS);

    return 0;
}
