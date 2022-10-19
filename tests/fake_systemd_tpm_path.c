#include <string.h>

extern int tpm2_find_device_auto(int log_level, char **ret) {
    (void) log_level;
    *ret = strdup(TPM_PATH);
    return 0;
}
