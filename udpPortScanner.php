<?php

/*
 * UDP portscanner
 *
 * This class implements a UDP portscanner.
 *
 * Usage:
 *
 *   include ('classes/udpPortScanner.inc');
 *
 *   $udpScanner = new udpPortScanner("$REMOTE_ADDR");
 *   $openPorts  = $udpScanner-> scan();
 *
 *   if (count($openPorts) == 0) {
 *       echo "no open UDP ports detected.<br/>";
 *   } else {
 *       echo "open UDP ports:<br/>";
 *
 *       foreach ($openPorts as $portNumber => $service) {
 *           echo "$portNumber ($service)<br/>";
 *       }
 *   }
 *
 *
 * copyright jason n. perkins (jperkins@sneer.org) 2001-10-15
 * version 1.0 (initial release) 2001-10-15
 * version 1.1 (port to PHP 5)
 */


class udpPortScanner
{
    var $cleanupIterations;
    var $endPort;
    var $output;
    var $socketTimeout;
    var $startPort;
    var $hostIp;
    var $timeout;

    var $openPorts = array();

    /*
     * udpPortScanner
     */

    // TODO: accept a hostname for the hostIp
    // TODO: accept IPv6 addresses
    // TODO: accept an array of host ips

    // TODO: validate that the starting port is between 1 and 65536
    // TODO: validate that the ending port is between 1 and 65536
    // TODO: validate that the ending port is ≥ the starting port
    function __construct($hostIp, $startPort = 1, $endPort = 1024, $output = 1)
    {
        $this->hostIp    = "udp://$hostIp";
        $this->startPort = $startPort;
        $this->endPort   = $endPort;
        $this->output    = $output;

        // TODO: verify that set_time_limit() is required
        set_time_limit(0);
    }

    /*
     * scan
     *
     * Do the networkProbe, then do the scan itself, then run our
     * method to test the results returned from our scan to eliminate
     * false postives. Finally, return an array indexed by the ports
     * that we found open.
     *
     */
    public function scan()
    {
        // test scan and setup scanner parameters
        echo "initial scan to determine network characteristics...<br/>";
        flush();

        $this->networkProbe();

        // conduct the scan
        for ($portNumber = $this->startPort; $portNumber <= $this->endPort; $portNumber++) {
            if ($this->output == 1) {
                echo "scanning port: $portNumber<br/>";
                flush();
            }

            if ($this->scanPort($portNumber)) {
                $service = getservbyport($portNumber, udp);
                $this->openPorts[$portNumber] = $service;
            }
        }

        $this->removeFalsePositives();

        // return the detected open ports array
        return $this->openPorts;
    }

    /*
     * scan
     *
     * Scan the specified port.
     *
     * First, a socket is opened to the specified port and then we set
     * the timeout of the function to the value that was determined in
     * the networkProbe method. We then send a single UDP packet to the
     * target machine. After the packet is sent, we enter a loop waiting
     * for a response. A host running nothing on that port will immediately
     * return an error. However, if the datagram is lost or that port is
     * open, nothing will be returned and the socket time's out. If the
     * socket times out, we return a 1 value (true), else we return a 0
     * value (false).
     */

    private function scanPort($portNumber)
    {
        // deal with exceptions thrown by fsockopen
        $handle = fsockopen(
          $this->hostIp,
          $portNumber,
          &$errno,
          &$errstr,
          2
        );

        if (!$handle) {
            echo "$errno : $errstr <br/>";
        }

        // TODO: verify that socket_set_timeout() is required
        socket_set_timeout($handle, $this->timeout);

        $write = fwrite($handle, "\x00");
        if (!$write) {
            echo "error writing to port: $index.<br/>";
            next;
        }

        $startTime = time();
        $header    = fread($handle, 1);
        $endTime   = time();
        $timeDiff  = $endTime - $startTime;

        if ($timeDiff >= $this->timeout) {
            fclose($handle);
            return 1;
        } else {
            fclose($handle);
            return 0;
        }
    }


    /*
     * removeFalsePositives
     *
     * Ititerate over $openPorts testing for false positives returned
     * from our main scan of the target ip. If a false positive is
     * found, we unset() that value from the array and continue the
     * processing of $openPorts.
     *
     * The number of iterations that is conducted was determined in the
     * networkProbe method. The array of tested ports is returned.
     */

    private function removeFalsePositives()
    {
        if (count($this->openPorts) > 0) {
            $noInitiallyOpenPorts = count($this->openPorts);

            if ($this->output == 1) {
                echo "<br/>";
                echo "$noInitiallyOpenPorts ports initially detected open.<br/>";
                echo "cleanup iterations: " . $this->cleanupIterations . "<br/>";
                echo "<br/>";
            }

            for ($index = 1; $index <= $this->cleanupIterations; $index++) {
                if ($this->output == 1) {
                    echo "current cleanup iteration: $index<br/>";
                }

                flush();

                foreach ($this->openPorts as $portNumber => $status) {
                    if (!$this->scanPort($portNumber)) {
                        unset($this->openPorts[$portNumber]);
                    }
                }
            }
        }

        return $this->openPorts;
    }

    /*
     * networkProbe
     *
     * We do an intial UDP port scan high in the port range. We're
     * doing this to minimize the detection of legitimate open ports so
     * that we can get an estimate of the number of UDP packets that are
     * being lost due to the network connection. We'll use this estimate
     * of lost packets to figure the number of cleanupIterations we'll need
     * to run. The formula to determine this is similar to one used to
     * calculate exponential rate of decay.
     *
     * From the UDP packets that don't timeout, we also establish
     * the standard deviation of how long it took them to completete the
     * round trip. This is used to setup a timeout value of 4 sigma from
     * the average round trip time for the socket_set_timeout function.
     * Because the socket_set_timeout currently won't except a value of
     * less than a second this is mainly an exercise in futility in terms
     * of minimizing program run time. If the socket_set_timeout function
     * is ever changed to allow a value of less than one second, then
     * under good network conditions we could expect a decrease in runtime
     * of up to a factor of five.
     *
     */

    private function networkProbe($noTrials = 100, $startPortNumber = 55000)
    {
        $endPortNumber = $startPortNumber + $noTrials;

        // temporarily set timeout to 2 seconds.
        // we'll modify this with the data that we get from this method
        $this->timeout = 2;

        // loop the ports that we're to scan
        for ($portNumber = $startPortNumber; $portNumber < $endPortNumber; $portNumber++) {
            $startTime = $this->getmicrotime();
            $result    = $this->scanPort($portNumber);
            $endTime   = $this->getmicrotime();
            $timeDiff  = $endTime - $startTime;

            if (!$result) {
                $responsesArray[] = $timeDiff;
                $totalTime += $timeDiff;
            }
        }

        $noResponses = count($responsesArray);

        // abort the scan if more than 40% of the datagrams timed out
        if ($noResponses < (.6 * $noTrial)) {
            echo "The connection is losing too many packets. Scan aborted. <br/>";
            exit;
        }

        $averageResponseTime   = $this->calculateAvgResponseTime($noResponses, $totalTime);
        $stdDeviation     = $this->calculateStdDeviation($responsesArray);
        $timeoutValue          = ceil($averageResponseTime + 4 * $stdDeviation);

        // % of datagrams that we sent in the trial that timeout
        $percentFalsePositives = ($noTrials - $noResponses) / $noTrials;

        // % of datagrams that we sent in the trial that didn't timeout
        $percentResponses      = $noResponses / $noTrials;

        // number of ports to be scanned in the real scan
        $portRange             = $this->endPort - $this->startPort + 1;

        // est number of false postivies we anticipate during the real scan
        $estFalsePositives     = $portRange * $percentFalsePositives;

        $this->cleanupIterations = $this->calculateNoIterations(
          $estFalsePositives,
          $percentResponses,
          $portRange
        );

        if ($this->output == 1) {
            echo "<br/>";
            echo "total time $totalTime<br/>";
            echo "timeout value: " . $this->timeout . "<br/>";
            echo "cleanup iterations: " . $this->cleanupIterations . "<br/>";
            echo "<br/>";
            flush();
        }
    }

    /*
     * getMicroTime
     *
     * Return the current time as seconds.microseconds format.
     * Found on php.net and used here without modification.
     */

    private function getMicroTime()
    {
        $t = microtime();
        $t = ((double) strstr($t, ' ') + (double) substr($t, 0, strpos($t, ' ')));

        return $t;
    }

    /*
     * calculateAvgResponseTime
     *
     * Returns the avg response time of the initial scan.
     */

    private function calculateAvgResponseTime($noResponses, $totalTime)
    {
        if ($noResponses == 0) {
            $averageResponseTime = 0;
        } else {
            $averageResponseTime = $totalTime / $noResponses;
        }

        return $averageResponseTime;
    }

    /*
     * calculateStdDeviation
     *
     * The standard deviation of the array of response times from the
     * preliminary scan.
     */

    private function calculateStdDeviation($responsesArray)
    {
        foreach ($responsesArray as $currentResponse) {
            $temp = pow(($averageResponseTime - $currentResponse), 2);
            $variance += $temp;
        }

        $stdDeviation = sqrt($variance);

        return $stdDeviation;
    }

    /*
     * calculateNoIterations
     *
     * Number of times that the ports will have to be scanned.
     */

    private function calculateNoIterations($estFalsePositives, $percentResponses, $portRange)
    {
        // we'll always have some cleanupIterations
        if ($noFalsePosititives == 0) {
            $cleanupIterations = 3;
        } else {
            $this->cleanupIterations = ceil(
              log($estFalsePositives) / $percentResponses
            );
        }

        if ($cleanupIterations < 5) {
            $cleanupIterations = 5;
        }

        return $cleanupIterations;
    }
}
