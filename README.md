# *LIT*MUS<sup>RT</sup> under *ROS* : LITROS

LITROS is a Linux daemon for executing ROS nodes as real-time tasks on LITMUS<sup>RT</sup>. It integrates ROS with LITMUS<sup>RT</sup> to enable temporally isolated execution of robotics software modules.

[LITMUS<sup>RT</sup>](http://www.litmus-rt.org/) stands for the *Linux Testbed for Multiprocessor Scheduling in Real-Time Systems* and enhances the Linux kernel with predictable scheduling and synchronization
policies.


LITROS executes seamlessly to the ROS framework, and manages the system calls for real-time execution
of ROS nodes. At this stage, only the nodes implemented with the C++ implementation
of ROS (roscpp) are supported. The responsibility of the application developer is to
specify a mapping between the ROS node that is to be contained in a reservation and the
temporal parameters of the reservation. The mapping associates a node ID with a set of
reservation parameters.
The parameters of each node are specified in a file with JSON format. The parameter file
is located in a directory that is defined when launching the daemon. LITROS inspects
every ROS node that has been launched by the framework. If the node that is launched
has temporal parameters specified under the parameter directory, LITROS ensures that
the node runs under the reservation in which the parameters are specified for.

## Dependencies

The dependencies of the daemon are listed below.
- A LITMUS<sup>RT</sup>-patched Linux kernel. In order to build (or to use the pre-patched OS image), follow the guide in https://wiki.litmus-rt.org/litmus/InstallationInstructions .
- Since LITROS relies on Netlink socket family to get the process creation/termination
events, the kernel is needed to be built with Netlink interface enabled.
This is done by enabling `COMPAT_NETLINK_MESSAGES` option on the kernel
configuration file.
- [*liblitmus*](https://github.com/LITMUS-RT/liblitmus), the userspace library of LITMUS<sup>RT</sup>
- [cJSON](https://github.com/DaveGamble/cJSON) library for parsing the node configuration files. The source code of the
library is included as a module on the LITROS source tree, therefore it is not
necessary download it separately. The build script of LITROS builds and installs
cJSON libraries automatically.
- Syslog server for logging the messages. When active, LITROS uses Syslog
protocol to write event messages.

The reservations used in this work are implemented in the **work-in-progress** reservation-based scheduling
plugin *ESPRESSO*. ESPRESSO plugin and its user-space stubs are available in the
wip-espresso-v12 branches of both LITMUS<sup>RT</sup> and liblitmus. Thus, both userspace and
the kernel of LITMUS<sup>RT</sup> has to be built by using that branch.

Since the cJSON library is included as a submodule, it is recommended to clone the repository with the following command:

`git clone --recursive https://github.com/mahircg/litros`

## Installation

Once the repository is cloned to the directory of the choice, the path to the liblitmus
must be specified in the makefile of LITROS. The directory of liblitmus is specified by
assigning the path to the `LIBLITMUS` variable in the Makefile of LITROS. Before the
daemon is built, liblitmus has to be successfully compiled first. LITROS can be then
simply build by the make command.

After the libraries are built, the installation script of LITROS creates the default configuration
files and folders under `/etc/litros` directory. Both the daemon and the build
script use the directory convention that is specified in `.config` file. Once the daemon
is installed, the configuration file directory where the node-to-reservation files to be
placed is determined by the `rt_folder` variable in `/etc/litros/litros.conf` file. When the
daemon starts, it checks for the configuration files under the directory that is pointed by
the `rt_folder` variable.

## Usage

The LITROS daemon has two parameters, as shown below. The options for the command
parameter are self-explaining. If desired, the configuration file directory can be changed
by "-d" argument.

```
-c, Command to perform. Options are: start, stop, restart
-d, Configuration file directory. By default, the directory is /etc/litros/rt_config
```

## Node Parameter Specification

For every node, the ROS middleware creates multiple threads to handle the communication,
polling and logging functions. LITROS offers the feature of assigning those threads
into separate reservations by specifying thread-to-reservation mappings. This feature,
however, is only available if the ROS middleware is modified by applying the patch
named `litros.patch` which is available under the top-level directory of LITROS. The patch does nothing but
naming the internal threads of the node. Thus, the middleware must be installed from
its source code if fine-grained control over internal ROS threads is required. Otherwise,
the management threads (polling, communication, etc.) share the same reservation with the node itself.

Node-to-thread mapping of a node is stored in JSON format. A separate configuration
file is necessary for every node and its threads that are to be contained in reservations.
The table below describes the set of attributes of a mapping between a ROS node (or thread of
a node) and a reservation.

| Attribute |                                 Explanation                                 |
|:---------:|:---------------------------------------------------------------------------:|
|   res_id  |             Reservation ID, which is unique on every processor.             |
|  res_str  |                           Type of the reservation.                          |
| partition |              Processor (or cluster) to assign the reservation.              |
|   period  |                           Period in milliseconds.                           |
|   budget  |                           Budget in milliseconds.                           |
|   offset  |                           Offset in milliseconds.                           |
|  priority |  Priority of the reservation. Valid only if the top-level scheduler is FP.  |
|  deadline | Deadline in milliseconds. If not specified, period is used as the deadline. |


If the application is multi-threaded and runs on unmodified ROS, then the threads need
to be named by the node developer if they are to be assigned to different reservations.
Thread of a node is identified by the node’s name followed by the thread’s name with
an underscore character in-between. So, the naming convention for identifying a node’s
thread is `<node_name>_<thread_name>`. 

**Important Note**: In its current shape, the naming convention for specifying thread to reservation mappings is not very practical and will change in the next version.

The following two sections explain the internal threads of a single node, and describes how those threads can be assigned to separate reservations.



## Mapping Threads to Reservations

LITROS offers fine-grained specification of temporal parameters for the internal threads of a
node. This property, however, comes at the expense of a small modification to the source
code of `roscpp`. As mentioned previously, LITROS relies on process names to manage
the execution mode of the nodes. On the other hand in Linux, whenever a process calls
`pthread_create` to create a POSIX thread, the new thread inherits the calling process’
name. Therefore, all internal threads and application threads of a ROS node are named
with the calling node’s process name. For identifying the threads based on their names,
we had to name them first. Therefore, we modified the source code of `roscpp` framework
for naming the threads.

### Internal Threads of ROS

Behind the scenes, `roscpp` creates multiple threads to handle tasks such as network
management. The user application runs unaware of these threads. LITROS allows
mapping those internal threads to separate reservations. For each node, the middleware
initializes the following singleton objects.
- `XMLRPCManager` for communications that involve the master node. A separate
thread is created for communicating with the master.
- `PollManager` for peer-to-peer data communication with other nodes. A separate
thread is created that monitors the file descriptors of peer nodes via poll() system
call.
- `ROSOutAppender` for logging messages through a special node named rosout.

Moreover, when a node is initialized, the ROS middleware creates a global callback queue
to store the pending callbacks for the subscribers of the node. A single-threaded ROS
application creates a thread that calls `ros::spin()` to iterate over and invoke all pending
callbacks one-by-one. `roscpp` also support multi-threaded spinning, where callbacks can
be called from multiple threads. As of this version of LITROS, we support reservation
mapping only for single-threaded spinning: a reservation mapping can be done for the
global callback queue thread. Note that the support for multi-threaded spinners is in
progress.

In conclusion, only XML-RPC, polling, logging and
callback queue threads of a node can be assigned into a separate reservation. All internal threads are identified with their corresponding abbreviations as listed below.

```
XML -> XML
Logging -> LOG
Global Callback Queue -> QUEUE
Polling -> Poll
```

### Patching ROS

The `roscpp` package of ROS is required to be modified in order to name the threads. Assuming the source code directory of ROS is available under `$ROS_DIR`, the patch can be applied after copying the patch file and navigating to `ros_comm` directory:

```bash
cp litros.patch $ROS_DIR/ros_comm/roscpp/clients
cd $ROS_DIR/ros_comm/roscpp/clients
patch < litros.patch
``` 

After patching, it is necessary to re-build the ROS middleware for the changes to take effect.

### Parameter Example

For example, the two configuration files below can be used for assigning a node named
talker and its XML thread to two separate reservations.

```json
{
    "res_str": "constant-bandwidth-server",
    "task_id": "talker",
    "partition" : 0,
    "priority" : 0,
    "period" : 100,
    "budget" : 50,
    "deadline" : 0,
    "offset" : 0,
    "res_id" : 100
}
```

```json
{
    "res_str": "constant-bandwidth-server",
    "task_id": "talker_XML",
    "partition" : 1,
    "priority" : 0,
    "period" : 100,
    "budget" : 50,
    "deadline" : 0,
    "offset" : 0,
    "res_id" : 100
}

```

## Example Usage

In this section, it is assumed that all above-mentioned requirements are met (LITMUS<sup>RT</sup> and LITROS installed, ROS patched).
The two configuration files for the node named `talker` are assumed to be present under `/etc/litros/rt_config` directory.

Before using the daemon, the default scheduling plugin of LITMUS<sup>RT</sup> must be set to ESPRESSO by using
the setsched tool that is available as part of liblitmus. Otherwise, the nodes cannot be
assigned to reservations and an error message will be logged.

```setsched ESPRESSO```

The list of available reservation implementations can be listed with `resctl -t` command.

After starting LITROS with `./litros -c start` command, the logs can be monitored under default syslog file (`/var/log/syslog` under Debian).

```
litrosd[3329]: reading configuration from /etc/litros/rt_config/Mapper_XML.json

litrosd[3329]: parsed JSON file Talker_XML.json

litrosd[3329]: node parameters:
      task_id:talker_XML    
      res_id:100    
      res_str:constant-bandwidth-server    
      partition:1    
      priority:0    
      period:100.000    
      budget:50.000    
      deadline::0.000    
      offset:0.000
litrosd[3329]: checking RT parameters
litrosd[3329]: RT parameters are valid
litrosd[3329]: config inserted into the list
litrosd[3329]: reading configuration from /etc/litros/rt_config/Mapper.json
litrosd[3329]: parsed JSON file Talker.json
  .
  .
  .
litrosd[3329]: config inserted into the list
 ```

After the daemon is initialized successively, every ROS node with a valid mapping will be assigned to the corresponding reservation.

Starting the `talker` node (under `test` package) with `rosrun test talker` command will trigger the daemon to transition the node process into real-time mode.

```
litrosd[3329]: trying to create R100

litrosd[3329]: create_reservation(rt_status->node) succeeded: tid: 3552, res_id: 100, task_id:talker
litrosd[3329]: be_migrate_thread_to_cpu(tid, rt_node->partition) succeeded: tid: 3552, res_id: 100, task_id:talker
litrosd[3329]: set_rt_task_param(tid, param) succeeded: tid: 3552, res_id: 100, task_id:talker
litrosd[3329]: sched_setscheduler(tid, SCHED_LITMUS, linux_param) ok.
litrosd[3329]: attach_node(rt_status, pid) succeeded: tid: 3552, res_id: 100, task_id:talker
kernel: [ 1414.010894] Setting up rt task parameters for process 3552.
litrosd[3329]: init_litmus() succeeded:  tid: 3552, res_id: 100, task_id:talker
litrosd[3329]: switched to RT mode
litrosd[3329]: talker forked talker_Poll with TID 3561
litrosd[3329]: talker_Poll does not have configuration file. It will be executed on reservation of talker
litrosd[3329]: talker forked talker_XML with TID 3562
litrosd[3329]: ROS node talker_XML has been started with PID 3562
  .
  .
  .
litrosd[3329]: init_litmus() succeeded: tid: 3562, res_id: 100, task_id:talker_XML
   ```
Since ROS middleware is patched and `roscpp` threads are named, the XML thread of the `talker` node can be executed in a separate reservation.

