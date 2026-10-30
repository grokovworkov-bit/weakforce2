/* TweakForce vendored fishhook.h — Facebook fishhook (MIT). Rebinds C symbols.
 * EN: Rebinds lazy/non-lazy symbols in Mach-O images. RU: Переназначает
 * символы в образах Mach-O. Source: github.com/facebook/fishhook */
#ifndef fishhook_h
#define fishhook_h
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct rebinding { const char *name; void *replacement; void **replaced; };
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);
int rebind_symbols_image(void *header, intptr_t slide,
                         struct rebinding rebindings[], size_t rebindings_nel);
#ifdef __cplusplus
}
#endif
#endif
