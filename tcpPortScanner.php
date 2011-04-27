<?

/*
 * TCP Portscanner
 *
 * Derived with permission from:
 *
 *     http://www.phpwizard.net/resources/tutorials/securing_servers.html
 *
 * Usage:
 *
 *  include ('classes/TcpPortScanner.php');
 *
 *  $tcpScanner = new TcpPortScanner("$REMOTE_ADDR");
 *  $openPorts  = $tcpScanner->scan();
 *
 *  if (count($openPorts) == 0) {
 *      echo "no open tcp ports detected.<br/>";
 *  } else {
 *      echo "open tcp ports:<br/>";
 *
 *      foreach ($openPorts as $portNumber => $service) {
 *          echo "$portNumber ($service)<br/>";
 *      }
 *  }
 *
 * @package default
 * @author Jason Perkins  (jperkins70@gmail.com)
 * @version 1.0
 * released on 2001-10-15
 *
 */

class TcpPortScanner {
    var $minPort;
    var $maxPort;
    var $targetIP;
    var $timeout;

    var $ports = array();

    public function __construct ($targetIP, $minPort=1, $maxPort=1024, $timeout=1) {
        $this->targetIP = $targetIP;
        $this->minPort  = $minPort;
        $this->maxPort  = $maxPort;
        $this->timeout  = $timeout;
    }

    /*
     *
     * Executes a scan against the target IP
     *
     * @return void
     * @author Jason Perkins
     *
     */

    public function scan () {
        set_time_limit(0);

        for ($index = $this-> minPort; $index <= $this-> maxPort; $index++) {
            echo "scanning port: $index<br/>";

            flush();

            $handle = fsockopen(
                $this-> targetIP,
                $index,
                $errno,
                $errstr,
                $this-> timeout
            );

            if ($handle) {
                $service              = getservbyport($index, "tcp");
                $this-> ports[$index] = "$service";

                fclose($handle);
            }
        }

    return $this-> ports;
    }
}
