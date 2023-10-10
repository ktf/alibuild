from shlex import quote  # Python 3.3+
from alibuild_helpers.cmd import getstatusoutput
from alibuild_helpers.log import debug

SL_COMMAND_TIMEOUT_SEC = 120
"""How many seconds to let any sl command execute before being terminated."""

def sapling(args, directory=".", check=True, prompt=True):
  debug("Executing sl %s (in directory %s)", " ".join(args), directory)
  # We can't use git --git-dir=%s/.git or git -C %s here as the former requires
  # that the directory we're inspecting to be the root of a git directory, not
  # just contained in one (and that breaks CI tests), and the latter isn't
  # supported by the git version we have on slc6.
  # Silence cd as shell configuration can cause the new directory to be echoed.
  err, output = getstatusoutput("""\
  set -e +x
  sl -R {directory} {args}
  """.format(
    directory=quote(directory),
    args=" ".join(map(quote, args)),
  ), timeout=SL_COMMAND_TIMEOUT_SEC)
  if check and err != 0:
    raise RuntimeError("Error {} from sl {}: {}".format(err, " ".join(args), output))
  return output if check else (err, output)
