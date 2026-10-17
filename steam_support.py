"""Conservative identification of conventional Windows Steam modules."""
STEAM_MODULES = frozenset({
    'steam_api.dll', 'steam_api64.dll', 'steamclient.dll', 'steamclient64.dll',
    'steam.dll', 'steamservice.dll', 'gameoverlayrenderer.dll',
    'gameoverlayrenderer64.dll', 'tier0_s.dll', 'tier0_s64.dll',
    'vstdlib_s.dll', 'vstdlib_s64.dll',
})


def is_steam_module(name):
    return name.replace('\\', '/').rsplit('/', 1)[-1].casefold() in STEAM_MODULES


def inventory(report):
    imports = [e for e in report['imports'] if is_steam_module(e['name'])]
    strings = [s for s in report.get('dll_strings_without_import', []) if is_steam_module(s)]
    return dict(static_imports=[e['name'] for e in imports],
                imported_functions=sum(len(e['symbols']) for e in imports),
                reference_candidates=sum(len(e['candidate_references']) for e in imports),
                string_indicators=strings,
                conclusion='static_steam_imports_found' if imports else 'no_static_steam_imports_found',
                limitation='No static import is not proof of complete Steam independence; dynamic loading and other modules may still require Steam.')
