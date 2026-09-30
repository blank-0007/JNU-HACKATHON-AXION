/* The protected workload: a stand-in payment service binary. The agent measures
 * this executable; replacing or patching it on disk shows up as a BINARY mismatch. */
#include <stdio.h>

int main(void) {
    puts("checkout-service 2.4.1: routing payments through the configured gateway");
    return 0;
}
