#ifndef CENTER_TEXT_H
#define CENTER_TEXT_H

/**
 * Centers the given text on a line with the specified width.
 *
 * @param text        The text string to be centered.
 * @param screen_width The total width of the output line.
 */
void center_text(const char *text, int screen_width);

/**
 * Centers the given text the specified number of times.
 *
 * @param text        The text string to be centered.
 * @param screen_width The total width of the output line.
 * @param lines      The number of times to print the centered text.
 */
void center_text_multiple(const char *text, int screen_width, int lines);

#endif /* CENTER_TEXT_H */
