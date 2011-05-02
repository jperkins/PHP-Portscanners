<?php

/*
 * TCP Portscanner
 *
 * Derived with permission from:
 *
 *     http://www.phpwizard.net/resources/tutorials/securing_servers.html
 *
 * Usage:
 *
 *   include ('classes/TcpPortScanner.php');
 *
 *   $tcpScanner = new TcpPortScanner("$REMOTE_ADDR");
 *   $openPorts  = $tcpScanner->scan();
 *
 *   if (count($openPorts) == 0) {
 *       echo "no open tcp ports detected.<br/>";
 *   } else {
 *       echo "open tcp ports:<br/>";
 *
 *       foreach ($openPorts as $portNumber => $service) {
 *           echo "$portNumber ($service)<br/>";
 *       }
 *   }
 *
 * @package default
 * @author Jason Perkins (jperkins70@gmail.com)
 * @version 1.0
 * released on 2001-10-15
 *
 */

class TcpPortScanner {
    var $startPort;
    var $endPort;
    var $hostIP;
    var $timeout;

    var $openPorts = array();


    // TODO: accept IPv6 addresses
    // TODO: accept an array of host ips
    // TODO: allow a hostname to be supplied
    // TODO: accept an array of hostnames

    // TODO: validate that the starting port is between 1 and 65536
    // TODO: validate that the ending port is between 1 and 65536

    // TODO: validate that the ending port is after the starting port
    public function __construct ($hostIP, $startPort=1, $endPort=1024, $timeout=1) {
        $this->startPort = $startPort;
        $this->endPort   = $endPort;
        $this->hostIP    = $hostIP;
        $this->timeout   = $timeout;
    }

    /*
     *
     * Scans the host IP
     *
     * @return void
     * @author Jason Perkins
     *
     */

    public function scan () {
        // TODO: verify that set_time_limit() is required
        set_time_limit(0);

        for ($index = $this->startPort; $index <= $this->endPort; $index++) {
            echo "scanning port: $index<br/>";

            flush();

            // TODO: deal with exceptions thrown by fsockopen
            $handle = fsockopen(
                $this->hostIP,
                $index,
                $errno,
                $errstr,
                $this->timeout
            );

            if ($handle) {
                $service = getservbyport($index, "tcp");
                $this->openPorts[$index] = "$service";

                fclose($handle);
            }
        }

        return $this->openPorts;
    }
}
