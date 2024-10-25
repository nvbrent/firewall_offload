# Testing the OPOF Software

Testing OPOF requires three distinct systems:
- The DPU:
  * opof agent
  * opof test driver
- The DPU's Host
  * traffic genrator/monitor
- An external system
  * traffic generator/monitor

```
    ┌-------------┐    ┌---------------┐    ┌---------------┐
    | DPU (Arm)   |    | DPU HOST (x86)|    | Ext HOST (x86)|
    | - OPOF      |    | - Traffic Gen |    | - Traffic Gen |
    | - Test Drv  |    |               |    |               |
    └-------------┘    └---------------┘    └---------------┘
         ||                  ||                  ||
    ┌-------------------------------┐            ||
    |   BlueField Embedded Switch   |            ||
    └-------------------------------┘            ||
                             ||                  ||
                        ┌-------------------------------┐
                        |   External Switch (Optional)  |
                        └-------------------------------┘
```

## Message Schemas (gRPC) Used by the Test

openoffload.proto schema:
- Test-Drv <-> OPOF: Test-Drv creates sessions to offload hairpin/drop operations on packets

opof_tester.proto schema:
- Test-Drv <-> DPU/Ext Host Traffic Gen: Test-Drv commands traffic to be generated and queries for received packets

## Operation

To execute the test, ssh into the DPU and:
1. Modify `test_conf.sh` to match your Hosts
2. Install ssh keys onto the DPU Host and External Host.
3. `cd` to the `test/opof_tester` directory
4. Run the `install_prereqs.sh` script to install the required python modules
5. Ensure the OPOF service is running. If an External Switch is in place, be sure
   to specify the `--dmac` argument to ensure hairpinned traffic returns to the Ext Host.
6. Execute `./run_test.py`

The test driver uses gRPC to drive the traffic generator(s), then configures sessions in the opof and measures the changes in the traffic flows.

The DPU and the external traffic generator may have an L2 switch connecting them. In this case, the opof service must be started with the dmac override option in order for the traffic generator/monitor to receive offloaded packet flows.

