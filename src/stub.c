/* vitarecomp runtime — placeholder.
 *
 * The runtime proper (CPU state, memory, semantic helpers, sceKernel/sceGxm
 * HLE) lands in phase 3. This file exists so the `vitarecomp` library target
 * is valid from the first commit, which keeps a consuming game repo's
 * add_subdirectory()/target_link_libraries() stable while the toolkit is still
 * only a container parser.
 */

int vitarecomp_placeholder(void);

int vitarecomp_placeholder(void) {
    return 0;
}
