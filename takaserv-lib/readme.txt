[allow.cfg and <nodename>.allow supports hostname,ip address and regular expression.]

The file 'allow.cfg' which has the client's list connectable to starsserver,
is changed to support the expression of the ip address in addition to the hostname,
and regular expression.

Example of "allow.cfg"
("#" character of first column is used for comment.)

# Example of allow.cfg
127.0.0.1
localhost
# IP address between 192.168.11.204 - 192.168.11.206
192.168.11.20[4-6]
# IP address matches 192.168.11. #now commented
#192.168.11.*

-------------------------
The file '<nodename>.allow' is optional which's used to limit the client
connectable to starsserver using nodename '<nodename>'
by the client's hostname or ip address information.
The file '<nodename>.allow' supports hostname and ip address and regular expression.

Example of "<nodename>.allow" are shown below.
("#" character of first column is used for comment.)

# Example of term1.allow
127.0.0.1
localhost
# IP address betweem 192.168.11.204 - 192.168.11.206
192.168.11.20[4-6]
# IP address matches 192.168.11. #now commented
#192.168.11.*


==========================================================================
[Reconnectable deny and allow.]
This version of kernel has reconnectable qualifying functions and it is
 in test fase.
Please note that the specifications might be changed in the future.

"reconnectable_deny.cfg" and "reconnectable_allow.cfg" under "takaserv-lib" are used
for checking limitation of reconnections. These files are simple text file and
they have reconnectable check list which are separated with LF(or CR + LF for Windows).

If the stars client which has same terminal name has already connected to stars when
trying to connect,
Kernel checkes reconnectable with "reconnectable_deny.cfg" first,
then the "terminal name" and "terminal name + host name" doesn't
match the deny list, it checks with "reconnectable_allow.cfg".
If the "terminal name" or "teminal name + host name" matches,
the connected client will be disconnected then new client will be connected.

Example of "reconnectable_deny.cfg" and "reconnectable_allow.cfg" are shown below.
("#" character of first column is used for comment.)

# Example of reconnectable_allow.cfg
# term1 from localhost can be reconnectable.
term1 localhost
# term2 from any host can be reconnectable.
term2


==========================================================================
[Command deny and allow.]
This version of kernel has command qualifying functions.

"command_deny.cfg" and "command_allow.cfg" under "takaserv-lib" are used
for checking limitation of commands. These files are simple text file and
they have command check list which are separated with LF(or CR + LF for Widows).

Kernel checkes a command with "command_deny.cfg" first, then the command doesn't
match the deny list, it checks with "command_allow.cfg". If the command muches,
it will be sent to corresponding client.

Example of "command_deny.cfg" and "command_allow.cfg" are shown below.
("#" character of first column is used for comment.)

# Example of command_deny.cfg
# Restrict SetValue command from term1 to ioc1 and ioc2.
#
term1>ioc1 SetValue
term1>ioc2 SetValue


# Example of command_allow.cfg
# Allow only hello command from term1 to System.
#
term1>System hello


==========================================================================
[Shutdown allow.]
New for Rust kernel version!
The Kernel check if the node name is in the shutdown_allow.cfg file. If the
node name matches the node that send the shutdown command, then the command
will be executed.

Example of "shutdown_allow.cfg" is shown below.
("#" character of first column is used for comment.)

# Example of shutdown_allow.cfg
# Only term1 can shutdown the stars server.
#
term1