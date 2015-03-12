#include <stdlib.h>
#include <termios.h>

static struct termios oldt;

//restore terminal settings
void restore_terminal_settings(void)
{
    //Apply saved settings
    tcsetattr(0, TCSANOW, &oldt); 
}

//make terminal read 1 char at a time
void disable_terminal_return(void)
{
    struct termios newt;
    
    //save terminal settings
    tcgetattr(0, &oldt); 
    //init new settings
    newt = oldt;  
    //change settings
    newt.c_lflag &= ~(ICANON | ECHO);
    //apply settings
    tcsetattr(0, TCSANOW, &newt);
    
    //make sure settings will be restored when program ends
    atexit(restore_terminal_settings);
}

int main()
{
    int ch;
    
    disable_terminal_return();
    
    printf("press your keyboard\n");
    /* Key reading loop */
    while (1) {
        ch = getchar();
        if (ch == 'Q') return 0;  /* Press 'Q' to quit program */
        printf("\tYou pressed %c\n", ch);
    }
    
    return 0;
}
