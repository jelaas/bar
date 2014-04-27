#include <stdlib.h>
#include <string.h>

#include "bar_rpm.h"
#include "jelist.h"

struct rpm *rpm_new()
{
	struct rpm *rpm;
	rpm = malloc(sizeof(struct rpm));
	if(!rpm) return (void*)0;
	memset(rpm, 0, sizeof(struct rpm));
	rpm->sigtags = jl_new();
	rpm->tags = jl_new();
	return rpm;
}
