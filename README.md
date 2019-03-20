# Organization

In order to gauge the health of a system one needs to check any number of things.

These things, or checks, can be logically grouped together. This is a source. A source consists of 1..n checks.

A check should be as atomic as possible to limit the scope and complexity, ideally returning a yes/no whether the check passes or fails. This is not always possible and that's ok.

At a higher level than source is product. The hierarchy looks like:

    ipahealthcheck
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

The base class for a check is ipahealthcheck.core.plugin::Plugin

The only method that needs to be implemented is check(). This implements the test against the system and should yield a Result object. Because check() is a generator multiple results can be yielded from a single check.

Typically each source defines its own plugin.py which contains the registry. This looks like:



        from ipahealthcheck.core.plugin import Registry

        registry = Registry()

A basic check module consists of:

        from ipahealthcheck.core.plugin import Plugin, Result
        from ipahealthcheck.core import constants
        from ipahealthcheck.mymodule.plugin import registry


        @registry
        class MyPlugin(Plugin):
            def check(self):
                yield Result(self, constants.SUCCESS)

# Return value

A check yields a Result. This contains the outcome of the check including:

* severity as defined in ipahealthcheck/core/constants.py
* msg containing a message to be displayed to the user.
* kw, a python dictionary of name value pairs that provide details on the error

The kw dict is meant to provide context for the check. Err on the side of
too much information.

msg and kw are optional if severity is SUCCESS.

If a check consist of only a single test then it is not required to yield
a Result, one marking the check as successful will be added automatically.

If a check is complex enough that it checks multiple values then it should
yield a SUCCESS Result() for each one.

A Result is required for every test done so that one can know that the
check was executed.

The runtime duration of each check will be calculated. The mechanism
differs depending on complexity.

A check should normally use the @duration decorator to track the
duration it took to execute the check.


        @registry
        class MyPlugin(Plugin):
            @duration
            def check(self):
                yield Result(self, constants.SUCCESS)


# Registering a source

The list of sources is stored in setup.py in the top-level of the tree.

Assuming it is contained in-tree it takes the form of:

'ipahealthcheck.<dir>': [
    'name = ipahealthcheck.<dir>.<file>'
]

For example, to add replication to the src/ipahealthcheck/ipa directory

    'ipahealthcheck.ipa': [
        'ipacerts = ipahealthcheck.ipa.certs',
        'ipafiles = ipahealthcheck.ipa.files',
        'ipakerberos = ipahealthcheck.ipa.kerberos',
        'replication = ipahealthcheck.ipa.replication',
    ],

If a new branch of sources is added a new registry is needed. This is
added into the ipahealthcheck.registry section in setup.py. If we decided
that replication didn't belong under ipahealthcheck.ipa but instead in
ipahealthcheck.ds it would look like:

    'ipahealthcheck.registry': [
        'ipahealthcheck.ipa = ipahealthcheck.ipa.plugin:registry',
        'ipahealthcheck.dogtag = ipahealthcheck.dogtag.plugin:registry',
        'ipahealthcheck.meta = ipahealthcheck.meta.plugin:registry',
        'ipahealthcheck.ds = ipahealthcheck.ds.plugin:registry',
    ],

and

    'ipahealthcheck.ds': [
        'replication = ipahealthcheck.ds.replication',
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
