# What is healthcheck?

It is an attempt to answer the question "Is my IPA installation working properly."

Major pain points in an IPA installation were identified and tests written to verify that the system is configured or running with expected settings.

The major areas currently covered are:

* Certificate configuration and expiration dates
* Replication errors
* Replication topology
* AD Trust configuration
* Service status
* File permissions of important configuration files
* Filesystem space

# How to use it?

Distributions can include a systemd timer which will executed the test nightly and log the output to /var/log/ipa/healthcheck. This can be the input into a monitoring system to track changes over time or to alert if a test goes from working to error or warning.

It can be run from the command-line as root as ipa-healthcheck. Running from the command-line by default will display the output to the console.

There is output for _all_ tests so we can be sure that an error condition isn't providing a false positive. The command-line option --failures-only will skip printing the SUCCESS conditions.

There are two main ways we expect that healthcheck will be executed:

1. Execute daily in cron or using a systemd timer, collect the output, and load it into an existing system monitoring system to track changes over time.
2. Run on an ad-hoc basis and look for errors

# What if I get an error or warning?

In general the output should contain enough information to provide a basic idea of why it is considered an error. If a specific value is expected then that will be provided along with the observed value. For example a number of files are checked for owner, group and permissions. If a value differs from the expected value then the expected and got values will be reported.

Running from the command-line will aid in ensuring that the condition is correct to what is expected. The basic idea is that it would be iterative:

1. ipa-healthcheck
2. manually address any errors

Repeat until until no errors are reported.

# What about false positives?

It is possible that some tests will need to be tweaked to accomodate real world situations. If you observe false positives then please open an issue at [https://github.com/freeipa/freeipa-healthcheck/issues](URL)

There is no way to suppress an error without making a change either in the test or in the system to accomodate the test requirements.

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

* result as defined in ipahealthcheck/core/constants.py
* msg containing a message to be displayed to the user.
* kw, a python dictionary of name value pairs that provide details on the error

The kw dict is meant to provide context for the check. Err on the side of
too much information.

msg and kw are optional if result is SUCCESS.

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

# Testing and development

The package can be tested and developed in a python virtual environment.

It requires a full freeIPA deployment so full set of system packages
need to be installed and an IPA master running.

To create the virtual environment run:

    % python3 -m venv --system-site-packages venv
    % venv/bin/pip install -e .

To use the environment

    % source venv/bin/activate

To run the healthchecks (must be done as root for proper results):

    # source venv/bin/activate
    # ipa-healthcheck

To run the tests execute the virtual environment:

    % pip install pytest
    % pytest

The configuration file and directory are not yet created so you'll need
to do that manually:

    # mkdir /etc/ipahealthcheck
    # echo "[default]" > /etc/ipahealthcheck/ipahealthcheck.conf
