# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/ulexec/Documents/clion-2018.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/ulexec/Documents/clion-2018.2/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ulexec/Documents/ELF-REsearch/libworm

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/worm_s.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/worm_s.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/worm_s.dir/flags.make

CMakeFiles/worm_s.dir/elfw.c.o: CMakeFiles/worm_s.dir/flags.make
CMakeFiles/worm_s.dir/elfw.c.o: ../elfw.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/worm_s.dir/elfw.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/worm_s.dir/elfw.c.o   -c /home/ulexec/Documents/ELF-REsearch/libworm/elfw.c

CMakeFiles/worm_s.dir/elfw.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/worm_s.dir/elfw.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ulexec/Documents/ELF-REsearch/libworm/elfw.c > CMakeFiles/worm_s.dir/elfw.c.i

CMakeFiles/worm_s.dir/elfw.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/worm_s.dir/elfw.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ulexec/Documents/ELF-REsearch/libworm/elfw.c -o CMakeFiles/worm_s.dir/elfw.c.s

CMakeFiles/worm_s.dir/injectw.c.o: CMakeFiles/worm_s.dir/flags.make
CMakeFiles/worm_s.dir/injectw.c.o: ../injectw.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/worm_s.dir/injectw.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/worm_s.dir/injectw.c.o   -c /home/ulexec/Documents/ELF-REsearch/libworm/injectw.c

CMakeFiles/worm_s.dir/injectw.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/worm_s.dir/injectw.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ulexec/Documents/ELF-REsearch/libworm/injectw.c > CMakeFiles/worm_s.dir/injectw.c.i

CMakeFiles/worm_s.dir/injectw.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/worm_s.dir/injectw.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ulexec/Documents/ELF-REsearch/libworm/injectw.c -o CMakeFiles/worm_s.dir/injectw.c.s

CMakeFiles/worm_s.dir/listw.c.o: CMakeFiles/worm_s.dir/flags.make
CMakeFiles/worm_s.dir/listw.c.o: ../listw.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/worm_s.dir/listw.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/worm_s.dir/listw.c.o   -c /home/ulexec/Documents/ELF-REsearch/libworm/listw.c

CMakeFiles/worm_s.dir/listw.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/worm_s.dir/listw.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ulexec/Documents/ELF-REsearch/libworm/listw.c > CMakeFiles/worm_s.dir/listw.c.i

CMakeFiles/worm_s.dir/listw.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/worm_s.dir/listw.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ulexec/Documents/ELF-REsearch/libworm/listw.c -o CMakeFiles/worm_s.dir/listw.c.s

# Object files for target worm_s
worm_s_OBJECTS = \
"CMakeFiles/worm_s.dir/elfw.c.o" \
"CMakeFiles/worm_s.dir/injectw.c.o" \
"CMakeFiles/worm_s.dir/listw.c.o"

# External object files for target worm_s
worm_s_EXTERNAL_OBJECTS =

lib/libworm_s.a: CMakeFiles/worm_s.dir/elfw.c.o
lib/libworm_s.a: CMakeFiles/worm_s.dir/injectw.c.o
lib/libworm_s.a: CMakeFiles/worm_s.dir/listw.c.o
lib/libworm_s.a: CMakeFiles/worm_s.dir/build.make
lib/libworm_s.a: CMakeFiles/worm_s.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C static library lib/libworm_s.a"
	$(CMAKE_COMMAND) -P CMakeFiles/worm_s.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/worm_s.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/worm_s.dir/build: lib/libworm_s.a

.PHONY : CMakeFiles/worm_s.dir/build

CMakeFiles/worm_s.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/worm_s.dir/cmake_clean.cmake
.PHONY : CMakeFiles/worm_s.dir/clean

CMakeFiles/worm_s.dir/depend:
	cd /home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ulexec/Documents/ELF-REsearch/libworm /home/ulexec/Documents/ELF-REsearch/libworm /home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug /home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug /home/ulexec/Documents/ELF-REsearch/libworm/cmake-build-debug/CMakeFiles/worm_s.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/worm_s.dir/depend

