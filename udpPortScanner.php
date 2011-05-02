<?php
/*
 *   a udp port scanner
 *
 *   this class implements a udp port scanner in php. a sample to
 *   use the class would be the following:
 *
 *   include ('classes/udpPortScanner.inc');
 *
 *   $udpScanner = new udpPortScanner("$REMOTE_ADDR");
 *   $ports = $udpScanner-> doScan();
 *   if (count($ports) == 0) {
 *       echo "no open udp ports detected.<br/>";
 *   } else {
 *       echo "open udp ports:<br/>";
 *       foreach ($ports as $portNumber => $service) {
 *           echo "$portNumber ($service)<br/>";
 *       }
 *   }
 *
 *
 *  copyright jason n. perkins (jperkins@sneer.org) 2001-10-15
 *  version 1.0 (initial release) 2001-10-15
 *  version 1.1 (port to PHP 5)
 */


class udpPortScanner
{
    var $targetIP;
    var $minPort;
    var $maxPort;
    var $timeout;
    var $socketTimeout;
    var $ports = array();
    var $cleanupIterations;
    var $output;


    /*
     *   udpPortScanner
     *
     *   class constructor. we initialize a couple of object variables here.
     */
    function udpPortScanner($targetIP, $minPort = 1, $maxPort = 1024, $output = 1)
    {
        // intitalize variables
        $this->targetIP = "udp://$targetIP";
        $this->minPort  = $minPort;
        $this->maxPort  = $maxPort;
        $this->output   = $output;
        set_time_limit(0);
    }

    /*
     *   doScan
     *
     *   the only other public method in the class. this method is similar to
     *   a c's main function; everything is run from here. we do our
     *   networkProbe, then conduct the scan itself, then run the method to
     *   test the results returned from our scan to eliminate false postives
     *   and finally return an array indexed by the ports that we found open.
     *
     */
    function doScan()
    {
        // conduct initial scan and setup scanner parameters
        echo "conducting initial scan to determine network characteristics...<br/>";
        flush();
        $this->_networkProbe();

        // conduct the scan
        for ($portNumber = $this->minPort; $portNumber <= $this->maxPort; $portNumber++) {
            if ($this->output == 1) {
                echo "scanning port: $portNumber<br/>";
                flush();
            }

            if ($this->_scanPort($portNumber)) {
                $service                  = getservbyport($portNumber, udp);
                $this->ports[$portNumber] = $service;
            }
        }

        // now call the method that will test for and remove detected fasle
        // positives
        $this->_removeFalsePositives();

        // return the detected open ports array
        return $this->ports;
    }

    /*
     *   _scanPort (as private as you can get in php)
     *
     *   the actual scanning of a specified port occurs here. first a socket
     *   is opened to the specified port and then we set the timeout of the
     *   function to the value that was determined in the _networkProbe
     *   function. we then send a single udp packet to the target machine.
     *   after the packet is sent, we enter a loop waiting for a response.
     *   a host running nothing on that port will immediately return an
     *   error. however, if the datagram is lost or that port is open,
     *   nothing will be returned and the socket time's out. if the socket
     *   timed out, we return a 1 value (true), else we return a 0
     *   value (false).
     */

    function _scanPort($portNumber)
    {
        $handle = fsockopen($this->targetIP, $portNumber, &$errno, &$errstr, 2);

        if (!$handle) {
            echo "$errno : $errstr <br/>";
        }

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
     *   _removeFalsePositives (as private as you can get in php)
     *
     *   we ititerate over the contents of the $ports array testing each
     *   port for false positives returned from our main scan of the target
     *   ip. if a false positive is found, we unset() that value from the
     *   array and continue the processing of the shortened array. the
     *   number of iterations that's conducted was determined in the
     *   _networkProbe method. the array of tested ports is returned.
     */

    function _removeFalsePositives()
    {
        if (count($this->ports) > 0) {
            $noInitiallyOpenPorts = count($this->ports);

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
                foreach ($this->ports as $portNumber => $status) {
                    if (!$this->_scanPort($portNumber)) {
                        unset($this->ports[$portNumber]);
                    }
                }
            }
        }

        return $this->ports;
    }

    /*
     *   _networkProbe (as private as you can get in php)
     *
     *   we conduct an intial udp port scan high in the port range. we're
     *   doing this to minimize the detection of legitimate open ports so
     *   that we can get an estimate of the number of udp packets that are
     *   being lost due to the network connection between the server and
     *   client. we'll use this estimate of lost packets to setup the
     *   number of cleanupIterations we have to run. the formula to determine
     *   this is a  logarithim similar to one used to calculate exponential
     *   rate of decay.
     *
     *   from the udp packets that don't timeout, we also establish
     *   the standard deviation of how long it took them to completete the
     *   round trip which is used to setup a timeout value of 4 sigma from
     *   the average round trip time for the socket_set_timeout function.
     *   because the socket_set_timeout currently won't except a value of
     *   less than a second this is mainly an exercise in futility in terms
     *   of minimizing program run time. If the socket_set_timeout function
     *   is ever changed to allow a value of less than one second, then
     *   under good network conditions we could expect a decrease in runtime
     *   of up to a factor of five.
     *
     */

    function _networkProbe($noTrials = 100, $startPortNumber = 55000)
    {
        $endPortNumber = $startPortNumber + $noTrials;


        // temporarily set timeout to 2 seconds. we'll modify this with the
        // data that we get from this method
        $this->timeout = 2;

        // setup a for loop to scan the ports
        for ($portNumber = $startPortNumber; $portNumber < $endPortNumber; $portNumber++) {
            $startTime = $this->_getmicrotime();
            $result    = $this->_scanPort($portNumber);
            $endTime   = $this->_getmicrotime();
            $timeDiff  = $endTime - $startTime;
            // echo "$timeDiff<br/>";

            if (!$result) {
                $responsesArray[] = $timeDiff;
                $totalTime += $timeDiff;
            }
        }


        $noResponses = count($responsesArray);

        // if more than 40% of the datagrams timed out, abort the scan
        if ($noResponses < (.6 * $noTrial)) {
            echo "The connection is losing too many packets. Scan aborted. <br/>";
            exit;
        }

        $averageResponseTime = $this->_calcAvgResponseTime($noResponses, $totalTime);

        $standardDeviation = $this->_calcStdrDeviation($responsesArray);

        // calculate the timeout value
        $timeoutValue = ceil($averageResponseTime + 4 * $standardDeviation);

        // calculate number of cleanup iterations we'll need

        // percentFalsePositive is the % of datagrams that we sent in
        // the trial that timed out
        $percentFalsePositives = ($noTrials - $noResponses) / $noTrials;

        // percentResponses is the % of datagrams that we sent in the trial
        // that returned (eg - didn't timeout)
        $percentResponses = $noResponses / $noTrials;

        // calculate the total number of ports to be scanned in the
        // real scan
        $portRange = $this->maxPort - $this->minPort + 1;

        // estFalsePositives is the estimated number of false scans we anticipate
        // getting from the real scan
        $estFalsePositives = $portRange * $percentFalsePositives;

        $this->cleanupIterations = $this->_calcNoIterations($estFalsePositives, $percentResponses, $portRange);

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
     *   _getMicroTime (as private as you can get in php)
     *
     *   this function return the current time as seconds.microseconds format.
     *   found on php.net and used here without modification.
     */

    function _getMicroTime()
    {
        $t = microtime();
        $t = ((double) strstr($t, ' ') + (double) substr($t, 0, strpos($t, ' ')));
        return $t;
    }

    /*
     *   _calcAvgResponseTime (as private as you can get in php)
     *
     *   returns the avg response time of the initial scan.
     */

    function _calcAvgResponseTime($noResponses, $totalTime)
    {
        if ($noResponses == 0) {
            $averageResponseTime = 0;
        } else {
            $averageResponseTime = $totalTime / $noResponses;
        }

        return $averageResponseTime;
    }

    /*
     *   _calcStdrDeviation (as private as you can get in php)
     *
     *   calculates and returns the standard deviation of the array of
     *   response times from the intital scan.
     */

    function _calcStdrDeviation($responsesArray)
    {
        foreach ($responsesArray as $currentResponse) {
            $temp = pow(($averageResponseTime - $currentResponse), 2);
            $variance += $temp;
        }

        $standardDeviation = sqrt($variance);
        return $standardDeviation;

    }

    /*
     *   _calcNoIterations (as private as you can get in php)
     *
     *   this function return the current time as seconds.microseconds format.
     *   found on php.net and used here without modification.
     */

    function _calcNoIterations($estFalsePositives, $percentResponses, $portRange)
    {
        // we're always going to have some cleanupIterations, so
        if ($noFalsePosititives == 0) {
            $cleanupIterations = 3;
        } else {
            $this->cleanupIterations = ceil(log($estFalsePositives) / $percentResponses);
        }

        if ($cleanupIterations < 5) {
            $cleanupIterations = 5;
        }

        return $cleanupIterations;
    }
}
?>


