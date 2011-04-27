
<?

    /*
    *   TcpPortScanner
    *
    *   a tcp port scanning class. derived (with permission) from the code and article at
    *   http://www.phpwizard.net/resources/tutorials/securing_servers.html
    *   written by jim barcelona (jim.barcelona@maguma.com). i simply rolled
    *   his code into this class for easier maintenance, use and distribution.
    *   a sample to use the class would be the following:
    *
    *   include ('classes/TcpPortScanner.php');
    *
    *   $tcpScanner = new TcpPortScanner("$REMOTE_ADDR");
    *   $ports      = $tcpScanner-> doScan();
    *
    *   if (count($ports) == 0) {
    *       echo "no open tcp ports detected.<br/>";
    *   } else {
    *       echo "open tcp ports:<br/>";
    *       foreach ($ports as $portNumber => $service) {
    *           echo "$portNumber ($service)<br/>";
    *       }
    *   }
    *
    *  copyright jason n. perkins (jason@somebodydial911.com) 2001-10-15
    *  version 1.0
    *  released on 2001-10-15
    */

    class TcpPortScanner {
        var $targetIP;
        var $minPort;
        var $maxPort;
        var $timeout;
        var $ports = array();

        public function __construct ($targetIP, $minPort=1, $maxPort=1024, $timeout=1) {
            $this->targetIP = $targetIP;
            $this->minPort = $minPort;
            $this->maxPort = $maxPort;
            $this->timeout = $timeout;
        }

        /*
        *   doScan
        *
        *   method that conducts the scan of the target ip. iterates through the port range
        *   and attempts to open a socket on each of the ports in turn. if there's a service
        *   on that port, then the handle will return true and we store the port number
        *   and the service on that port in an array. the array is returned when the loop ends.
        */

        public function scan () {
            set_time_limit(0);

            for ($index = $this-> minPort; $index <= $this-> maxPort; $index++)
            {
                echo "scanning port: $index<br/>";
                flush();
                $handle = fsockopen($this-> targetIP, $index, $errno, $errstr, $this-> timeout);

                if ($handle) {
                    $service = getservbyport($index, "tcp");
                    $this-> ports[$index] = "$service";
                    fclose($handle);
                }
            }

        return $this-> ports;
        }
    }
