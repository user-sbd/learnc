NEEDS_RECOMPILE=0
for c_file in *.c; do
    if [ "$c_file" -nt "main" ]; then
        NEEDS_RECOMPILE=1
        break
    fi
done

# Set the build command: compile only if needed, then run
if [ $NEEDS_RECOMPILE -eq 1 ]; then
    BUILD_CMD="gcc *.c -o main && ./main"
else
    BUILD_CMD="./main"
fi

# Open a new horizontal tmux pane and run the command there
tmux neww -c "#{pane_current_path}" "$BUILD_CMD ; exec zsh"

exit 0
