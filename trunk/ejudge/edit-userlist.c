/* -*- mode:c; coding: koi8-r -*- */
/* $Id$ */

#include <ncurses/ncurses.h>
#include <ncurses/menu.h>
#include <ncurses/panel.h>

static WINDOW *root_window;
static MENU *main_menu;
static WINDOW *main_menu_window;
static ITEM *main_menu_items[5];
static PANEL *main_menu_panel;

static void
display_main_menu(void)
{
  int req_rows, req_cols;
  int c, cmd;

  scale_menu(main_menu, &req_rows, &req_cols);
  main_menu_window = newwin(req_rows + 2, req_cols + 2, 5,
                            (80 - req_cols - 2) / 2);
  main_menu_panel = new_panel(main_menu_window);
  set_menu_win(main_menu, main_menu_window);

 restart_main_menu:
  show_panel(main_menu_panel);
  post_menu(main_menu);
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q':
    case 'c': case 'C':
    case 'u': case 'U':
    case '\n': case '\r':
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    case KEY_HOME:
      cmd = REQ_FIRST_ITEM;
      break;
    case KEY_END:
      cmd = REQ_LAST_ITEM;
      break;
    case KEY_NPAGE:
      cmd = REQ_SCR_UPAGE;
      break;
    case KEY_PPAGE:
      cmd = REQ_SCR_DPAGE;
      break;
    }
    if (cmd != -1) {
      menu_driver(main_menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(main_menu);
  hide_panel(main_menu_panel);
}

int
main(int argc, char **argv)
{
  if (!(root_window = initscr())) return 1;
  cbreak();
  noecho();
  nonl();
  intrflush(stdscr, FALSE);
  keypad(stdscr, TRUE);

  main_menu_items[0] = new_item("View contests", 0);
  main_menu_items[1] = new_item("View users", 0);
  main_menu_items[2] = new_item("Quit", 0);
  main_menu = new_menu(main_menu_items);
  display_main_menu();

  clear();
  refresh();
  free_menu(main_menu);
  endwin();
  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -g -Wall edit-userlist.c -o edit-userlist -lpanel -lmenu -lncurses"
 * End:
 */
