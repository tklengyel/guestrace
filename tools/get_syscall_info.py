#!/usr/bin/python

"""
                              INFO
                            --------
This file when run as a script will look at a Linux operating system
and gather several pieces of information. It will gather the mapping 
between system call numbers and system call names through the use of 
ausyscall. It will also attempt to pull several headers from the 
Linux kernel source tree of the specific version of the kernel
running in order to gather information on the arguments of the
system calls on the system. This will generate a C enum in the form
of a header file and a file with a program to translate raw information
from registers to a formatted string in a C source file. These files
can be used with the guesttrace tool, but the included files have been
hand modified to support more formatted printing of each system call.
"""



import subprocess
import urllib2
import re
import time
from optparse import OptionParser

#           INFORMATION CLASSES
#         -----------------------
# Classes to hold information used in
# generating the C source files for
# use with trace syscalls
class syscall_data:
    """This class stores the information of a single system call, The data
    includes the syscall name, number and argument information.
    """

    def __init__(self, syscall_number, syscall_name):
        """The __init__ method is called to create the object.
        
        Inputs:
            syscall_number -- integer
            syscall_name   -- string

        Output:
            syscall_data object
        """
        self.__number = syscall_number      # store the syscall number
        self.__name = syscall_name          # store the syscall name
        self.__arg_names = []               # create an empty list to hold argument names
        self.__arg_types = []               # create an empty list to hold argument types
        self.__arg_printf_types = []        # create an empty list to hold the type to use with printf in the C source
        self.__arg_formats = []             # create an empty list to hold the format symbols for the printf format string in the C source


    def __repr__(self):
        """The __repr__ fucntion creates a string representation of the object

        Inputs:
            none

        Outputs:
            string representation of syscall_data object
        """
        syscall_str = self.get_syscall_name() + "("
        args_count = self.get_args_count()

        for arg_num in range(args_count):
            syscall_str += self.get_arg_type(arg_num) + " " 
            syscall_str += self.get_arg_name(arg_num) + ", "
            
            if arg_num == args_count - 1:       # remove the trailing space and comma if on the
               syscall_str = syscall_str[:-2]   # last argument

        return syscall_str + ");"
        
    def get_syscall_name(self):
        """Return the syscall name"""
        return self.__name

    def get_args_count(self):
        """Return the number of arguments"""
        return len(self.__arg_types)

    def get_arg_type(self, arg_num):
        """Return the argument type of the argument at index arg_num"""
        return self.__arg_types[arg_num]

    def get_arg_name(self, arg_num):
        """Return the name of the argument at index arg_num"""
        return self.__arg_names[arg_num]
	
    def get_arg_printf_type(self, arg_num):
	return self.__arg_printf_types[arg_num]

    def get_arg_format(self, arg_num):
	return self.__arg_formats[arg_num]

    def add_argument(self, arg_type, arg_name = ""):
        """Add an argument to the syscall. This method will append a value
        to each of the argument information lists

        Input:
            arg_type -- string
            arg_name -- string -- default = ""

        No Output
        """
        self.__arg_types.append(arg_type)
        
        if arg_name == "":                                                     # make the name of the argument argN where N is
            self.__arg_names.append("arg{0}".format(self.get_args_count()))    # the index of the argument in case a name is not provided
        else:
            self.__arg_names.append(arg_name)

        arg_formats = self.__get_printf_format_type(arg_type)
        self.__arg_printf_types.append(arg_formats[0])
        self.__arg_formats.append(arg_formats[1])
        
    def __get_printf_format_type(self, arg_type):
        """Return the type that will be used in the C printf function"""
        uint_args = ["unsigned int", "qid_t", "uid_t", "gid_t", "clockid_t", "timer_t", "unsigned long", "size_t", "unsigned", "umode_t", "old_uid_t", "old_gid_t", "u64"]   
        int_args = ["int", "pid_t", "key_t", "mqd_t", "key_serial_t"]
        lint_args = ["loff_t", "long"]

        if "*" in arg_type:
            return ("unsigned long", '0x%"PRIx64"')
        
        for arg in uint_args:
            if arg in arg_type:
                return ("unsigned long", "%lu")

        for arg in int_args:
            if arg in arg_type:
                return ("int", "%i")

        for arg in lint_args:
            if arg in arg_type:
                return ("long int", "%li")

        else:
            return ("unsigned long", '0x%"PRIx64"')

class kernel_data:
    """Holds data about the kernel the script is being run on""" 
    
    def __init__(self, version, get_kernel_source):
        """Called on object instantiation"""
        self.__name = self.__set_name(version)
        self.__version = version
        self.__version_short = self.__set_short_version(version)
        self.__arch = self.__set_arch(version)
        self.__syscall_header_src = []
        
        if get_kernel_source:
            self.__syscall_header_src = self.__fetch_syscall_header_src()  
    
    def __repr__(self):
        """Return string representation of the kernel_data"""
        return self.get_kernel_version()
            
    def get_kernel_name(self):
        """Return the kernel name"""
        return self.__name
    
    def get_kernel_version(self):
        """Return the long version of the kernel"""
        return self.__version

    def get_kernel_version_short(self):
        """Return the short kernel version number"""
        return self.__version_short

    def get_kernel_arch(self):
        """Return the kernel architechture"""
        return self.__arch
    
    def get_header_src(self):
        """Returns the list of lines from the source header files"""
        return self.__syscall_header_src

    def __set_name(self, version):
        """Set the name of the kernel based on the version"""
        return version.split("_")[0]   

    def __set_short_version(self, version):
        """Set the short kernel version number based on the version"""
        return ".".join(version.split("_")[1].split(".")[:2])        

    def __set_arch(self, version):
        """Set the kernel architecture based on the version"""
        return version.split("_")[1].split(".")[4]
    
    def __fetch_syscall_header_src(self):
        """Attempts to get the two header files that contain the syscall prototypes form online first then locally"""
        linux_h_url = "http://lxr.free-electrons.com/source/include/linux/syscalls.h?v={0};raw=1".format(self.get_kernel_version_short())
        arch_h_url = "http://lxr.free-electrons.com/source/arch/{0}/include/asm/syscalls.h?v={1};raw=1".format(self.get_kernel_arch(), self.get_kernel_version_short())

        try:
            linux_h_src = urllib2.urlopen(linux_h_url)  # opens the url as a file object so normal file
            arch_h_src = urllib2.urlopen(arch_h_url)    # methods work
            linux_h = linux_h_src.readlines()
            linux_h.extend(arch_h_src.readlines())
            return linux_h

        except urllib2.URLError:
            print "Can not open URL's to pull source from online, attempting to open files locally!"    
            

        try:
            linux_h_src = open("linux_syscalls.h", "r")     # local files must follow the naming convention
            arch_h_src = open("arch_syscalls.h", "r")
            linux_h = linux_h_src.readlines()
            linux_h.extend(arch_h_src.readlines())
            return linux_h
       
        except IOError:
            print "Could not open files locally!"
            print "Could not get source!"
        

       


#           DATA GATHERING FUNCTIONS
#         ----------------------------
# Gather information about syscalls and the system
# the script is run on
def get_kernel_info(get_kernel_source):
    """Get kernel information and create a kernel_data object"""
    uname_output = subprocess.check_output(["uname", "-a"]).strip().split(" ")
    kernel_version = "{0}_{1}".format(uname_output[0], uname_output[2])
    return kernel_data(kernel_version, get_kernel_source)


def get_syscall_numbers():
    """For each syscall number, parse the name and create a syscall_data object"""
    syscall_number = 0
    syscall_name = subprocess.check_output(["ausyscall", "{0}".format(syscall_number)], stderr=subprocess.STDOUT)  # ausyscall maps syscall numbers to names   
    syscall_map = {}
    syscall_order = []
    
    while (True):
        syscall_name = "sys_" + syscall_name.strip()
        syscall_map[syscall_name] = syscall_data(syscall_number, syscall_name)
        syscall_order.append(syscall_name)
        syscall_number += 1

        try: 
            syscall_name = subprocess.check_output(["ausyscall", "{0}".format(syscall_number)], stderr=subprocess.STDOUT)
            if syscall_name[0] == "_":
                syscall_name = syscall_name[1:]
    
        except subprocess.CalledProcessError:
            return (syscall_map, syscall_order)

#       PARSING FUNCTIONS
#     ---------------------
# Parse the data gathered from the data
# gethering functions
def extract_syscall_prototypes(source_data):
    """Extract the system call prototypes from the source header file data"""
    curr_syscall = ""
    syscall_prototypes = []

    line = 0
    end = len(source_data)

    while (line < end):
        if "asmlinkage" == source_data[line].split(" ")[0]:
            curr_syscall = source_data[line].strip()
            line += 1
            while ("#" not in source_data[line] and "/*" not in source_data[line] and "asmlinkage" not in source_data[line]):
                curr_syscall += " " + source_data[line].strip()
                line += 1
            syscall_prototypes.append(curr_syscall)
        else:
            line += 1

    return syscall_prototypes

def parse_syscall_protos(syscall_prototypes, syscall_map):
    """Parse the syscall prototypes to add arguments to their 
    respective syscall_data objects"""
    invalid_names = ["int", "long", "*"] # takes care of protos with no arg names
     
    for syscall in syscall_prototypes:
        curr_syscall = re.findall('sys.*', syscall)[0].strip()         # strip the type before the syscall
        curr_syscall = curr_syscall.split("(")
        syscall_name = curr_syscall[0].strip()

        # syscall name and proto dont match so we fix that here
        if syscall_name == "sys_pwrite64":
            syscall_name = "sys_pwrite"
        if syscall_name == "sys_pread64":
            syscall_name = "sys_pread"
        
        # only want to add information to syscalls that we have in our map
        # which was generated with ausyscall      
        if syscall_name in  syscall_map:
            
            # parse arguments
            curr_args = curr_syscall[1].split(", ")
            if curr_args[0] == "void);":    # no arguemnts if the firs arg is void
                continue

            for arg in curr_args:
                
                if arg[-2:] == ");":        # remove the end for the last arg  
                    arg = arg[:-2]
                split_arg = arg.split(" ")  # split the arg to get the name and type
                arg_name = split_arg[len(split_arg) - 1]    # last of the split is the name
                arg_type = " ".join(split_arg[:-1])         # join all but the last for the type

                if arg_name != "" and arg_name[0] == "*":   # check to see if its a pointer because 
                    arg_name = arg_name[1:]                 # the * will be with name
                    arg_type += " *"                        # swap the * to be with the type

                if arg_name in invalid_names:               # some protos dont have names for args
                    arg_type += " " + arg_name              # so we fix that here
                    arg_name = ""
            
                syscall_map[syscall_name].add_argument(arg_type, arg_name)  # add the argument to the proper syscall
    
    return syscall_map

#           SOURCE CREATION FUNCTIONS
#         -----------------------------
# Create C source files for running with trace syscalls
def create_enum_src(syscall_order, kernel_info):
    """Create a C enum of each syscall on the system
     in a file named syscall_enum.h"""
    # generate beginning of source file 
    enum_str = "/* Generated on {0} on {1}*/\n\n".format(kernel_info.get_kernel_version(), time.strftime("%d %b %Y %H:%M:%S", time.localtime()))
    enum_str += "#ifndef SYSCALL_ENUM_H\n"
    enum_str += "#define SYSCALL_ENUM_H\n\n"
    enum_str += "enum syscalls {\n"
    
    # generate the actual enum list
    for syscall in range(len(syscall_order)):
        enum_str += "\t{0},\t\t\t/* {1} */\n".format(syscall_order[syscall].upper(), syscall) # want the enums to be all caps
    
    # generate the end of the file    
    enum_str = enum_str[:-2] + "\n"
    enum_str += "};\n\n"
    enum_str += "#endif"

    # write to syscall_enum.h
    f = open("syscall_enum.h", "w+")
    f.write(enum_str)
    f.close()

def create_syscall_translations(syscall_map, syscall_order,  kernel_info):
    """Create a C source file that will translate all syscalls and args to
    readable data"""
    # generate the beginning of the file
    func_str = "/* Generated on {0} on {1} */\n\n".format(kernel_info.get_kernel_version(), time.strftime("%d %b %Y %H:%M:%S", time.localtime()))

    includes = ["stdlib.h", "string.h", "stdio.h", "inttypes.h", "libvmi/libvmi.h", "libvmi/events.h"]  # list of C libraries to include
    for lib in includes:                                                                                # generate include statements for
        func_str += "#include <{0}>\n".format(lib)                                                      # each one

    func_str += '#include "syscall_enum.h"\n\n'                                                         # also include our enum

    # generate the print_syscall_info functions
    func_str += "void print_syscall_info(vmi_instance_t vmi, vmi_event_t *event) {\n\n"
    func_str += "\tchar *name;\n"                                                   # name used by every case
    func_str += "\treg_t syscall_number= event->regs.x86->rax;\n"                   # rax used by every case
    func_str += "\tvmi_pid_t pid = vmi_dtb_to_pid(vmi, event->regs.x86->cr3);\n\n"  # pid used by every case
    func_str += "\tswitch (syscall_number) {\n\n"                                   # start the giant switch

    # generate the case statement for each syscall
    for syscall in syscall_order:
        func_str += create_case_statement(syscall_map[syscall])

    # generate the default statement and end the function
    func_str += "\t\tdefault:\n"
    func_str += "\t\t{\n"
    func_str += '\t\t\tprintf("pid: %u syscall: unmapped syscall number: %lu\\n", pid, (unsigned long)syscall_number);\n'
    func_str += "\t\t}\n"
    func_str += "\t}\n"
    func_str += "}\n\n"

    # generate the print_sysret_info function
    func_str += "void print_sysret_info(vmi_instance_t vmi, vmi_event_t *event) {\n"
    func_str += "\treg_t syscall_return = event->regs.x86->rax;\n"
    func_str += "\tvmi_pid_t pid = vmi_dtb_to_pid(vmi, event->regs.x86->cr3);\n"
    func_str += '\tprintf("pid: %u return: 0x%"PRIx64"\\n", pid, syscall_return);\n'
    func_str += "}"

    # write all the functions to translate_syscalls.c
    f = open("translate_syscalls.c", "w+")
    f.write(func_str)
    f.close

def create_case_statement(syscall_data):
    """Generate the case statement for a single syscall"""
    # generate the start of the case 
    func_str = "\t\tcase {0}:\n".format(syscall_data.get_syscall_name().upper())
    func_str += "\t\t{\n"
    func_str += '\t\t\tname = "{0}";\n'.format(syscall_data.get_syscall_name())

    # call the correct function to create the printf statement based on
    # the number of args
    if 1 == syscall_data.get_args_count():
	func_str += create_printf_statement_1(syscall_data)
    elif 2 == syscall_data.get_args_count():
	func_str += create_printf_statement_2(syscall_data)
    elif 3 == syscall_data.get_args_count():
	func_str += create_printf_statement_3(syscall_data)
    elif 4 == syscall_data.get_args_count():
	func_str += create_printf_statement_4(syscall_data)
    elif 5 == syscall_data.get_args_count():
	func_str += create_printf_statement_5(syscall_data)
    elif 6 == syscall_data.get_args_count():
	func_str += create_printf_statement_6(syscall_data)
    else:
        func_str += '\t\t\tprintf("pid: %u syscall: %s()\\n", pid, name);\n'
    
    #finish out the case statement    
    func_str += "\t\t\tbreak;\n"
    func_str += "\t\t}\n\n"
    return func_str

# each of the following functions reads the needed registers 
# and creates a unique C printf statement based on the number 
# of args of the syscall
 
def create_printf_statement_1(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))
    
    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0})'.format(syscall_data.get_arg_format(0))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi'.format(syscall_data.get_arg_printf_type(0))
    func_str += ');\n'
    return func_str

def create_printf_statement_2(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))
    func_str += '\t\t\treg_t rsi = event->regs.x86->rsi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(1), syscall_data.get_arg_name(1))

    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0}, {1})'.format(syscall_data.get_arg_format(0), syscall_data.get_arg_format(1))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi, ({1})rsi'.format(syscall_data.get_arg_printf_type(0), syscall_data.get_arg_printf_type(1))
    func_str += ');\n'
    return func_str

def create_printf_statement_3(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))
    func_str += '\t\t\treg_t rsi = event->regs.x86->rsi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(1), syscall_data.get_arg_name(1))
    func_str += '\t\t\treg_t rdx = event->regs.x86->rdx;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(2), syscall_data.get_arg_name(2))

    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0}, {1}, '.format(syscall_data.get_arg_format(0), syscall_data.get_arg_format(1))
    func_str += '{0})'.format(syscall_data.get_arg_format(2))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi, ({1})rsi, '.format(syscall_data.get_arg_printf_type(0), syscall_data.get_arg_printf_type(1))
    func_str += '({0})rdx'.format(syscall_data.get_arg_printf_type(2))
    func_str += ');\n'
    return func_str

def create_printf_statement_4(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))    
    func_str += '\t\t\treg_t rsi = event->regs.x86->rsi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(1), syscall_data.get_arg_name(1))
    func_str += '\t\t\treg_t rdx = event->regs.x86->rdx;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(2), syscall_data.get_arg_name(2))
    func_str += '\t\t\treg_t r10 = event->regs.x86->r10;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(3), syscall_data.get_arg_name(3))

    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0}, {1}, '.format(syscall_data.get_arg_format(0), syscall_data.get_arg_format(1))
    func_str += '{0}, {1})'.format(syscall_data.get_arg_format(2), syscall_data.get_arg_format(3))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi, ({1})rsi, '.format(syscall_data.get_arg_printf_type(0), syscall_data.get_arg_printf_type(1))
    func_str += '({0})rdx, ({1})r10'.format(syscall_data.get_arg_printf_type(2), syscall_data.get_arg_printf_type(3))
    func_str += ');\n'
    return func_str

def create_printf_statement_5(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))    
    func_str += '\t\t\treg_t rsi = event->regs.x86->rsi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(1), syscall_data.get_arg_name(1))
    func_str += '\t\t\treg_t rdx = event->regs.x86->rdx;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(2), syscall_data.get_arg_name(2))
    func_str += '\t\t\treg_t r10 = event->regs.x86->r10;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(3), syscall_data.get_arg_name(3))
    func_str += '\t\t\treg_t r8 = event->regs.x86->r8;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(4), syscall_data.get_arg_name(4))

    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0}, {1}, '.format(syscall_data.get_arg_format(0), syscall_data.get_arg_format(1))
    func_str += '{0}, {1}, '.format(syscall_data.get_arg_format(2), syscall_data.get_arg_format(3))
    func_str += '{0})'.format(syscall_data.get_arg_format(4))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi, ({1})rsi, '.format(syscall_data.get_arg_printf_type(0), syscall_data.get_arg_printf_type(1))
    func_str += '({0})rdx, ({1})r10, '.format(syscall_data.get_arg_printf_type(2), syscall_data.get_arg_printf_type(3))
    func_str += '({0})r8'.format(syscall_data.get_arg_printf_type(4))
    func_str += ');\n'
    return func_str

def create_printf_statement_6(syscall_data):
    func_str = '\t\t\treg_t rdi = event->regs.x86->rdi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(0), syscall_data.get_arg_name(0))    
    func_str += '\t\t\treg_t rsi = event->regs.x86->rsi;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(1), syscall_data.get_arg_name(1))
    func_str += '\t\t\treg_t rdx = event->regs.x86->rdx;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(2), syscall_data.get_arg_name(2))
    func_str += '\t\t\treg_t r10 = event->regs.x86->r10;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(3), syscall_data.get_arg_name(3))
    func_str += '\t\t\treg_t r8 = event->regs.x86->r8;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(4), syscall_data.get_arg_name(4))
    func_str += '\t\t\treg_t r9 = event->regs.x86->r9;\t\t/* {0} {1} */\n'.format(syscall_data.get_arg_type(5), syscall_data.get_arg_name(5))

    func_str += '\t\t\tprintf("pid: %u syscall: %s'
    func_str += '({0}, {1}, '.format(syscall_data.get_arg_format(0), syscall_data.get_arg_format(1))
    func_str += '{0}, {1}, '.format(syscall_data.get_arg_format(2), syscall_data.get_arg_format(3))
    func_str += '{0}, {1})'.format(syscall_data.get_arg_format(4), syscall_data.get_arg_format(5))
    func_str += '\\n", pid, name, '
    func_str += '({0})rdi, ({1})rsi, '.format(syscall_data.get_arg_printf_type(0), syscall_data.get_arg_printf_type(1))
    func_str += '({0})rdx, ({1})r10, '.format(syscall_data.get_arg_printf_type(2), syscall_data.get_arg_printf_type(3))
    func_str += '({0})r8, ({1})r9'.format(syscall_data.get_arg_printf_type(4), syscall_data.get_arg_printf_type(5))
    func_str += ');\n'
    return func_str   


#       MAIN FUNCTION
#     -----------------
# Puts all the fucntions together to create
# a C enum as a header file and a C file
# containg functions to translate syscall
# data to a readable string
def main(get_kernel_source):
    """This function gets information on the kernel the script is running on,
    gathers a mapping of syscall names to syscall numbers for teh kernel it
    is running on, parses Linux source files for syscall prototypes, parses the
    prototypes to generate a complete object which holds a syscall name number and
    all information about its arguments and using this data generates two C files
    for use with trace_syscalls."""
    print "Getting kernel info!"
    kernel_info = get_kernel_info(get_kernel_source)

    print "Getting syscall info! takes a few seconds..."
    (syscall_map, syscall_order) = get_syscall_numbers()
    
    if get_kernel_source:
        print "Gathering syscall prototypes!"
        syscall_protos = extract_syscall_prototypes(kernel_info.get_header_src())
        
        print "Parsing prototypes!"
        syscall_map_complete = parse_syscall_protos(syscall_protos, syscall_map)
        
    else:
        print "Skipped functions invloving the linux source headers!"

    print "Generating syscall_enum.h!"
    create_enum_src(syscall_order, kernel_info)

    print "Generating translate_syscalls.c!"
    #create_syscall_translations(syscall_map, syscall_order, kernel_info)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-n", "--no_source",dest = "get_source",  default = True, action = "store_false", help = "Don't look for linux source files")
    (options, args) = parser.parse_args() 
    main(options.get_source)









