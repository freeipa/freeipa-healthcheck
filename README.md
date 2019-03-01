# Organization

In order to gauge the health of a system one needs to check any number of things.

These things, or checks, can be logically grouped together. This is a source. A source consists of 1..n checks.

A check should be as atomic as possible to limit the scope and complexity, ideally returning a yes/no whether the check passes or fails. This is not always possible and that's ok.

At a higher level than source is product. The hierarchy looks like:

    idmcheck
      product
        source
          check
          check
          ...
        source
          check
          ...

A source provides a registry so its checks are discoverable.

# Writing a check module

The base class for a check is idmcheck.core.plugin::Plugin

The only method that needs to be implemented is check(). This implements the test against the system and should return either a Result or a Results object.

Typically each source defines its own plugin.py which contains the registry. This looks like:



        from idmcheck.core.plugin import Registry

        registry = Registry()

A basic check module consists of:

        from idmcheck.core.plugin import Plugin, Result
        from idmcheck.core import constants
        from idmcheck.mymodule.plugin import registry


        @registry
        class MyPlugin(Plugin):
            def check(self):
                return Result(self, constants.SUCCESS)

# Return value

A check returns either a Result or Results object. This contains the outcome of the check including:

* severity as defined in idmcheck/core/constants.py
* msg containing a message to be displayed to the user.
* kw, a python dictionary of name value pairs that provide details on the error

msg and kw are optional if severity is SUCCESS.

# Registering a source

The list of sources is stored in setup.py in the top-level of the tree.

Assuming it is contained in-tree it takes the form of:

'idmcheck.<dir>': [
    'name = idmcheck.<dir>.<file>'
]

For example, to add replication to the src/idmcheck/ipa directory

    'idmcheck.ipa': [
        'ipacerts = idmcheck.ipa.certs',
        'ipafiles = idmcheck.ipa.files',
        'ipakerberos = idmcheck.ipa.kerberos',
        'replication = idmcheck.ipa.replication',
    ],

If a new branch of sources is added a new registry is needed. This is
added into the idmcheck.registry section in setup.py. If we decided
that replication didn't belong under idmcheck.ipa but instead in
idmcheck.ds it would look like:

    'idmcheck.registry': [
        'idmcheck.ipa = idmcheck.ipa.plugin:registry',
        'idmcheck.dogtag = idmcheck.dogtag.plugin:registry',
        'idmcheck.meta = idmcheck.meta.plugin:registry',
        'idmcheck.ds = idmcheck.ds.plugin:registry',
    ],

and

    'idmcheck.ds': [
        'replication = idmcheck.ds.replication',
    ],

# Execution

It is possible to execute a single check or all checks in a single source by passing --source and/or --check on the command-line. This is intended to help user's quickly ensure that something is fixed by re-running a check after making a change.

# Output

Output is controlled via Output plugins. These take the global Results object and iterate over it to produce output in the desired format.

A custom Output class must implement the render method which generates the output.

A bare-bones output class is:

        @output_registry
        class Basic(Output):
            def render(self, data):
                output = [x for x in data.output()]
                print(output)

An output object can declare its own options by adding a tuple named options to the class in the form of (arg_name, dict(argparse options).

An example to provide a way to read and re-parse existing results:

        options = (
            (--input-file', dict(dest='infoile', help='File to translate')),
        )

# Meta

The meta source is intended to collect basic information about the run such as the host it is run on and the time it was run.