add_kpm_module(wxshadow
    wxshadow.c
    wxshadow_pgtable.c
    wxshadow_handlers.c
    wxshadow_bp.c
    wxshadow_scan.c
)

# Build client tool (userspace)
add_executable(wxshadow_client wxshadow_client.c)
target_compile_options(wxshadow_client PRIVATE -O2 -static)
target_link_options(wxshadow_client PRIVATE -static)

# PMD split test tool (userspace)
add_executable(test_pmd_split test_pmd_split.c)
target_compile_options(test_pmd_split PRIVATE -O2 -static)
target_link_options(test_pmd_split PRIVATE -static)
