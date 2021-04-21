# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("EHSN")

# Include sub-projects.
add_subdirectory ("EHSN")

# Add source to this project's executable.
add_executable (Sandbox "Sandbox.cpp")

# Set required libraries
target_link_libraries (
	Sandbox EHSN
)

# Set include directories
target_include_directories (Sandbox PUBLIC "EHSN/include")
