from util import raises
from idmcheck.core.plugin import Plugin, Registry

def test_Registry():
    """
    Test the `idmcheck.core.Registry` class
    """
    class plugin1(Plugin):
        pass

    class plugin2(Plugin):
        pass

    # Create a registry
    r = Registry()

    # Check that TypeError is raised trying to register something that isn't
    # a class:
    p = plugin1(r)
    e = raises(TypeError, r, p)
    assert str(e) == 'plugin must be callable; got %r' % p

    # Register the plugins
    r(plugin1)
    r(plugin2)

    # TODO: enforce plugin uniqueness

    # Test registration
    names = [p.__class__.__name__ for p in r.get_plugins()]
    assert(names == ['plugin1', 'plugin2'])
