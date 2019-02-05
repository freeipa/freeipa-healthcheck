import pkg_resources

def main():
    api = object()
    plugins = []

    for ep in pkg_resources.iter_entry_points('idmcheck.ipa'):
        register = ep.resolve()
        plugins.extend(register(api))

    for plugin in plugins:
        plugin.check()
