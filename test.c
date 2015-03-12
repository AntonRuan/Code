#include<stdio.h>
#include<math.h>
struct pos {
	int x;
	int y;
};

void main()
{
	struct pos snake[3] = {{1,2},{3,4},{5,6}};
	printf("%d\n",snake[1].x);
	printf("%d\n",snake[1].y);
#if 0
	unsigned short a = 0x01;
	printf("%d\n",a);
	unsigned short b = 0x02;

	printf("%d\n",a|b);
	printf("%d\n",a&b);
#endif
#if 0
 	int value;
	float i;
	for ( i = 0; i < 128; i++)
	{
        	value = 32 + 32*sin(i/4);
        	printf("%d\n",value);
	}
#endif

}

