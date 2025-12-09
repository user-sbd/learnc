#define MATE_IMPLEMENTATION // Adds function implementations
#include "mate.h"

i32 main() {
  StartBuild();
  {
    Executable executable = CreateExecutable((ExecutableOptions){
        .output = "main",   // output name, in windows this becomes `main.exe` automatically
        .flags = "-Wall -g" // adds warnings and debug symbols
    });

    // Files to compile
    AddFile(executable, "./main.c");

    // Compiles all files parallely with samurai
    InstallExecutable(executable);

    RunCommand(executable.outputPath);
  }
  EndBuild();
}
